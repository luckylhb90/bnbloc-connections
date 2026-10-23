// Package secretenv fills the process environment from AWS Secrets
// Manager before anything reads it: a deployment that keeps the
// component's credential there names the secret (SecretIDEnv) instead of
// putting the value in the pod's environment.
//
// The secret's SecretString is either a JSON object of environment names to
// string values (each fills a variable the environment leaves empty), or a
// plain string, which is the value of Fallback (the component credential).
// A variable set explicitly always wins.
package secretenv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// Environment names of the bootstrap.
const (
	SecretIDEnv = "BNBLOC_AWS_SECRET_ID"
	RegionEnv   = "BNBLOC_AWS_REGION"
)

// Getter reads one secret (secretsmanager.Client).
type Getter interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Load fills the environment from the secret SecretIDEnv names (nothing
// when it is unset) and reports the variables it set. The AWS credentials
// are the default chain's (the pod's IAM role on EKS).
func Load(fallback string) ([]string, error) {
	id := strings.TrimSpace(os.Getenv(SecretIDEnv))
	if id == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var opts []func(*awsconfig.LoadOptions) error
	if region := strings.TrimSpace(os.Getenv(RegionEnv)); region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load the AWS configuration: %w", err)
	}
	return LoadFrom(ctx, secretsmanager.NewFromConfig(cfg), id, fallback)
}

// LoadFrom is Load with a given client.
func LoadFrom(ctx context.Context, c Getter, id, fallback string) ([]string, error) {
	out, err := c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(id)})
	if err != nil {
		return nil, fmt.Errorf("read secret %q: %w", id, err)
	}
	if out.SecretString == nil {
		return nil, fmt.Errorf("secret %q has no SecretString", id)
	}
	values, err := parse(*out.SecretString, fallback)
	if err != nil {
		return nil, fmt.Errorf("secret %q: %w", id, err)
	}
	var set []string
	for k, v := range values {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			continue
		}
		if err := os.Setenv(k, v); err != nil {
			return nil, err
		}
		set = append(set, k)
	}
	sort.Strings(set)
	return set, nil
}

func parse(raw, fallback string) (map[string]string, error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "{") {
		if trimmed == "" {
			return nil, fmt.Errorf("the secret is empty")
		}
		return map[string]string{fallback: trimmed}, nil
	}
	var values map[string]string
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return nil, fmt.Errorf("expected a JSON object of environment names to string values, or a plain value: %w", err)
	}
	return values, nil
}
