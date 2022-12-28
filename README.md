# Traffic Lite

This GitHub Action offers a simple way to preserve your repository's traffic data beyond the usual [14-day limit](https://github.com/isaacs/github/issues/399). It uses the [Repository traffic API](https://docs.github.com/en/rest/metrics/traffic?apiVersion=2022-11-28) to capture clone and view counts, logging the results in JSON format to a file of your choosing. You can use the [EndBug/add-and-commit](https://github.com/EndBug/add-and-commit) action to commit the result to your Git repository or even publish it to an external service like S3.

## Getting started

### Personal Access Token

You'll first need to create a Personal Access Token (PAT) to allow access to the repository traffic API. Follow [these instructions](https://docs.github.com/en/enterprise-server@3.4/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) to create your PAT with the **public_repo** scope.

Next, add the PAT to your repository's encrypted secrets following [these instructions](https://docs.github.com/en/actions/security-guides/encrypted-secrets#creating-encrypted-secrets-for-a-repository). You can choose any name you want; but, if you're looking for a suggestion, **GH_ACCESS_TOKEN** works well.

## Sample workflow

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
