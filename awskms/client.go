// SPDX-FileCopyrightText: Copyright 2023 Prasad Tengse
// SPDX-License-Identifier: MIT

package awskms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var _ Client = (*kms.Client)(nil)

// AWS KMS Asymmetric KMS client.
// For all uses this is equivalent to [github.com/aws/aws-sdk-go-v2/service/kms.Client].
// In AWS SDK v2, service interfaces are not generated.
// This implements extremely limited set of AWS KMS Client methods so that
// it can be mocked in unit tests. This is not a complete interface for
// AWS KMS client. This only supports limited number of methods required
// for testing. Outside of unit tests you can always pass
// [github.com/aws/aws-sdk-go-v2/service/kms.Client], as it always implements
// this interface.
//
// This interface may be backward incompatible between minor versions.
type Client interface {
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}
