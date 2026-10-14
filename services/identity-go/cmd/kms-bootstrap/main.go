// Command kms-bootstrap creates the AWS keys and aliases the identity service
// expects, skipping any alias that already exists. Run it once per account
// and region; it is safe to run again.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"tallowbrook.example/identity/internal/kmsbootstrap"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(context.Background(), log); err != nil {
		log.Error("bootstrap failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger) error {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	api := kms.NewFromConfig(cfg)
	for _, k := range kmsbootstrap.Keys() {
		_, err := api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(k.Alias)})
		if err == nil {
			log.Info("exists", "alias", k.Alias)
			continue
		}
		var nf *types.NotFoundException
		if !errors.As(err, &nf) {
			return fmt.Errorf("%s: %w", k.Alias, err)
		}
		out, err := api.CreateKey(ctx, &kms.CreateKeyInput{
			KeySpec:     k.Spec,
			KeyUsage:    k.Usage,
			Description: aws.String("identity-go: " + k.Alias),
			Tags:        []types.Tag{{TagKey: aws.String("service"), TagValue: aws.String("identity")}},
		})
		if err != nil {
			return fmt.Errorf("%s: create: %w", k.Alias, err)
		}
		if _, err := api.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String(k.Alias), TargetKeyId: out.KeyMetadata.KeyId}); err != nil {
			return fmt.Errorf("%s: alias: %w", k.Alias, err)
		}
		log.Info("created", "alias", k.Alias, "key", aws.ToString(out.KeyMetadata.KeyId))
	}
	return nil
}
