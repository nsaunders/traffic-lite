# Traffic Lite

This GitHub Action offers a simple way to preserve your repository's traffic data beyond the usual [14-day limit](https://github.com/isaacs/github/issues/399). It uses the [Repository traffic API](https://docs.github.com/en/rest/metrics/traffic?apiVersion=2022-11-28) to capture clones and views, logging the results in JSON format to a file of your choosing.

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
