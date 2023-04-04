package awskms_test

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/tprasadtp/cryptokms/awskms/internal/testdata"
)

var (
	_ kms.EndpointResolver = (*endpointResolver)(nil)
)

// endpointResolver Implements kms.EndpointResolver.
type endpointResolver struct{}

func (e *endpointResolver) ResolveEndpoint(region string, options kms.EndpointResolverOptions) (aws.Endpoint, error) {
	return aws.Endpoint{
		URL: testdata.KMSEndpoint,
	}, nil
}
