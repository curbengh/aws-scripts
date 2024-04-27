# CloudFront as reverse proxy to httpbin

Inspect _optional_ request headers added by [CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html) before forwarding to the origin ([httpbin.org](https://httpbin.org) in this case). Those headers can be configured through [origin request policy](https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cloudfront/OriginRequestPolicy.html) ([example](../waf-cdk/cloudfront-waf/)).

This is particularly useful to troubleshoot geoblocking and TLS policies that you may have configured in CloudFront.

Once deployed, cdk will output the CloudFront domain (xxx.cloudfront.net). Send a GET request to "https://xxx.cloudfront.net/get" or any API path listed in [httpbin.org](https://httpbin.org/). The CloudFront distribution acts as a reverse proxy to httpbin.

There is no default IP or geographic restriction on this CloudFront stack.
