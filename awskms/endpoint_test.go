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
	if testdata.KMSEndpoint != "" {
		return aws.Endpoint{
			URL: testdata.KMSEndpoint,
		}, nil
	}
	// returning EndpointNotFoundError will,
	// allow the service to fallback to it's default resolution.
	return aws.Endpoint{}, &aws.EndpointNotFoundError{}
}
