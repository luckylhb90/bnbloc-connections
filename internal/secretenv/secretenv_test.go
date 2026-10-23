package secretenv

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fake struct {
	value string
	err   error
}

func (f fake) GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(f.value)}, nil
}

func TestJSONFillsEmptyVariablesOnly(t *testing.T) {
	t.Setenv("BNBLOC_CONNECTIONS_SECRET", "")
	t.Setenv("BNBLOC_CONNECTIONS_NAME", "explicit")
	set, err := LoadFrom(context.Background(), fake{value: `{"BNBLOC_CONNECTIONS_SECRET":"whsec_x","BNBLOC_CONNECTIONS_NAME":"other"}`}, "id", "BNBLOC_CONNECTIONS_SECRET")
	if err != nil || strings.Join(set, ",") != "BNBLOC_CONNECTIONS_SECRET" || os.Getenv("BNBLOC_CONNECTIONS_SECRET") != "whsec_x" || os.Getenv("BNBLOC_CONNECTIONS_NAME") != "explicit" {
		t.Fatalf("set = %v, %v", set, err)
	}
}

func TestPlainValueIsTheCredential(t *testing.T) {
	t.Setenv("BNBLOC_CONNECTIONS_SECRET", "")
	if _, err := LoadFrom(context.Background(), fake{value: " whsec_plain \n"}, "id", "BNBLOC_CONNECTIONS_SECRET"); err != nil || os.Getenv("BNBLOC_CONNECTIONS_SECRET") != "whsec_plain" {
		t.Fatalf("plain = %q %v", os.Getenv("BNBLOC_CONNECTIONS_SECRET"), err)
	}
}

func TestFailuresAreReported(t *testing.T) {
	if _, err := LoadFrom(context.Background(), fake{err: errors.New("access denied")}, "id", "X"); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("err = %v", err)
	}
	if _, err := LoadFrom(context.Background(), fake{value: `{"A":7}`}, "id", "X"); err == nil {
		t.Fatal("a non-string value passes")
	}
}
