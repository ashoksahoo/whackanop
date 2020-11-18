package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
	"regexp"
	"time"
)

// Op represents a mongo operation.
type Op struct {
	ID          int    `bson:"opid"`
	Active      bool   `bson:"active"`
	Op          string `bson:"op"`
	SecsRunning int    `bson:"secs_running"`
	Namespace   string `bson:"ns"`
	Query       bson.M `bson:"query"`
}

// OpKiller kills a mongo op. Interface mostly for testing.
type OpKiller interface {
	Kill(op Op) error
}

// MongoOpKiller implements OpKiller on a real mongo database.
type MongoOpKiller struct {
	Client mongo.Client
}

// Kill uses the $cmd.sys.killop virtual collection to kill an operation.
func (mko MongoOpKiller) Kill(op Op) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return mko.Client.Database("admin").Collection("$cmd.sys.killop").FindOne(ctx, bson.M{"op": op.ID}).Decode(nil)
}

// OpFinder finds mongo operations. Interface mostly for testing.
type OpFinder interface {
	Find(query bson.M) ([]Op, error)
}

// MongoOpFinder implements OpFinder on a real mongo database.
type MongoOpFinder struct {
	Client mongo.Client
}

// Find operations matching a query.
func (mfo MongoOpFinder) Find(query bson.M) ([]Op, error) {
	var result struct {
		Inprog []Op `bson:"inprog"`
	}
	collection := mfo.Client.Database("admin").Collection("$cmd.sys.inprog")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := collection.FindOne(ctx, query).Decode(&result)
	return result.Inprog, err
}

// WhackAnOp periodically finds and kills operations.
type WhackAnOp struct {
	OpFinder OpFinder
	OpKiller OpKiller
	Query    bson.M
	Tick     <-chan time.Time
	Debug    bool
	Verbose  bool
}

// Run polls for ops, killing any it finds.
func (wao WhackAnOp) Run() error {
	for range wao.Tick {
		ops, err := wao.OpFinder.Find(wao.Query)
		if err != nil {
			return fmt.Errorf("whackanop: error finding ops %s", err)
		} else if wao.Verbose {
			log.Printf("found %d ops", len(ops))
		}
		for _, op := range ops {
			q, _ := json.Marshal(op.Query)
			log.Printf("opid=%d ns=%s op=%s secs_running=%d query=%s\n", op.ID,
				op.Namespace, op.Op, op.SecsRunning, q)
			if wao.Debug {
				continue
			}
			log.Printf("killing op %d", op.ID)
			if err := wao.OpKiller.Kill(op); err != nil {
				return fmt.Errorf("whackanop: error killing op %s", err)
			}
		}
	}
	return nil
}

func validateMongoURL(mongourl string) error {
	if matched, err := regexp.MatchString(`.*connect=direct(&.*|$)`, mongourl); err != nil {
		return err
	} else if !matched {
		return fmt.Errorf("must specify 'connect=direct' in mongourl")
	}
	return nil
}

func getSecret(secretName string, region string) (string, error) {

	//Create a Secrets Manager client
	svc := secretsmanager.New(session.New(),
		aws.NewConfig().WithRegion(region))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	// In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
	// See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html

	result, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				fmt.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())

			case secretsmanager.ErrCodeInternalServiceError:
				// An error occurred on the server side.
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())

			case secretsmanager.ErrCodeInvalidParameterException:
				// You provided an invalid value for a parameter.
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())

			case secretsmanager.ErrCodeInvalidRequestException:
				// You provided a parameter value that is not valid for the current state of the resource.
				fmt.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())

			case secretsmanager.ErrCodeResourceNotFoundException:
				// We can't find the resource that you asked for.
				fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return "", err
	}

	// Decrypts secret using the associated KMS CMK.
	// Depending on whether the secret is a string or binary, one of these fields will be populated.
	var secretString, decodedBinarySecret string
	if result.SecretString != nil {
		secretString = *result.SecretString
		return secretString, nil
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			fmt.Println("Base64 Decode Error:", err)
			return "", err
		}
		decodedBinarySecret = string(decodedBinarySecretBytes[:len])
		return decodedBinarySecret, nil
	}
}

func main() {
	flags := flag.NewFlagSet("whackanop", flag.ExitOnError)
	mongourl := flags.String("mongourl", "mongodb://localhost:27017/?connect=direct",
		"mongo url to connect to. Must specify connect=direct to guarantee admin commands are run on the specified server.")
	interval := flags.Int("interval", 1, "how often, in seconds, to poll mongo for operations")
	querystr := flags.String("query", `{"op": "query", "secs_running": {"$gt": 60}}`, "query sent to db.currentOp()")
	debug := flags.Bool("debug", true, "in debug mode, operations that match the query are logged instead of killed")
	version := flags.Bool("version", false, "print the version and exit")
	verbose := flags.Bool("verbose", false, "more verbose logging")

	secretManager := flags.Bool("enableawssecret", false, "Enable SecretManager")
	if *secretManager {
		secretName := flags.String("secretname", "whackanop",
			"SecretManager Name to connect")
		region := flags.String("region", "ap-southeast-1",
			"SecretManager Name to connect")
		secretPath := flags.String("secretpath", "local",
			"SecretManager Path to connect")
		var secretString, secretErr = getSecret(*secretName, *region)
		if secretErr != nil {
			log.Fatal(secretErr)
		}
		secretBytes := []byte(secretString)
		var raw map[string]interface{}
		if err := json.Unmarshal(secretBytes, &raw); err != nil {
			log.Fatal(err)
		}
		*mongourl = fmt.Sprintf("%v", raw[*secretPath])
	}

	flags.Parse(os.Args[1:])
	if *version {
		//fmt.Println(Version)
		os.Exit(0)
	}
	var query bson.M
	if err := json.Unmarshal([]byte(*querystr), &query); err != nil {
		log.Fatal(err)
	}

	if err := validateMongoURL(*mongourl); err != nil {
		log.Fatal(err)
	}
	log.Printf("mongourl=%s interval=%d debug=%t query=%#v", *mongourl, *interval, *debug, query)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))

	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	log.Printf("mongourl=%s interval=%d debug=%t query=%#v", *mongourl, *interval, *debug, query)

	wao := WhackAnOp{
		OpFinder: MongoOpFinder{*client},
		OpKiller: MongoOpKiller{*client},
		Query:    query,
		Tick:     time.Tick(time.Duration(*interval) * time.Second),
		Debug:    *debug,
		Verbose:  *verbose,
	}
	if err := wao.Run(); err != nil {
		log.Fatal(err)
	}
}
