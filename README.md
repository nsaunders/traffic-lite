# Traffic Lite

This GitHub Action offers a simple way to preserve your repository's traffic data beyond the usual [14-day limit](https://github.com/isaacs/github/issues/399). It uses the [Repository Traffic API](https://docs.github.com/en/rest/metrics/traffic?apiVersion=2022-11-28) to capture clone and view counts, logging the results in JSON format to a file of your choosing. You can use the [EndBug/add-and-commit](https://github.com/EndBug/add-and-commit) action to commit the result to your Git repository or even publish it to an external service like S3.

## Getting started

### Personal Access Token

You'll first need to create a Personal Access Token (PAT) to allow access to the repository traffic API. Follow [these instructions](https://docs.github.com/en/enterprise-server@3.4/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) to create your PAT with the **public_repo** scope.

Next, add the PAT to your repository's encrypted secrets following [these instructions](https://docs.github.com/en/actions/security-guides/encrypted-secrets#creating-encrypted-secrets-for-a-repository). You can choose any name you want; but, if you're looking for a suggestion, **GH_ACCESS_TOKEN** works well.

### Workflow configuration

> **Note**
> This section focuses on configuring this action. For a complete workflow you can use, see [Sample workflow](#sample-workflow) below.

You'll need to add a step like this to your GitHub Actions workflow file.

```yaml
- uses: nsaunders/traffic-lite@v0.1.2
  with:
    path: meta/traffic.json
    repo: ${{ github.repository }}
    token: ${{ secrets.GH_ACCESS_TOKEN }}
```

#### Inputs

| Name | Description |
|-|-|
| **path** | The path (relative to the workspace) where traffic data will be written in JSON format. If the file does not exist, the it will be created automatically. Otherwise, new data will be added to it while preserving any existing data. |
| **repo** | The repository whose traffic to monitor in _owner/repository_ format. A typical value, obtained from the [github context](https://docs.github.com/en/actions/learn-github-actions/contexts#github-context), would be `${{ github.repository }}`. |
| **token** | The PAT used to access the Repository Traffic API |

## Sample workflow

traffic.yml:
```yaml
name: Traffic

on:
  schedule: 
    - cron: "45 23 * * 0"

jobs:
  update:
    name: Update

    runs-on: ubuntu-latest

    env:
      TRAFFIC_PATH: meta/traffic.json

    steps:
      - uses: actions/checkout@v2

      - uses: nsaunders/traffic-lite@v0.1.2
        with:
          path: ${{ env.TRAFFIC_PATH }}
          repo: ${{ github.repository }}
          token: ${{ secrets.GH_ACCESS_TOKEN }}

      - name: Commit update
        uses: EndBug/add-and-commit@v9
        with:
          add: ${{ env.TRAFFIC_PATH }}
          author_name: GitHub Actions
          author_email: 41898282+github-actions[bot]@users.noreply.github.com
          message: Log repository traffic.
```
