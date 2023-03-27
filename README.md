# DCNM Prometheus Exporter


DCNM Alarms Exporter is a Prometheus exporter that retrieves alarms from Cisco's Data Center Network Manager (DCNM) and exposes them as Prometheus metrics. This enables monitoring and alerting on DCNM alarms using Prometheus and its ecosystem.

## Features

- Exposes the total number of ongoing alarms as a Prometheus metric
- Exposes individual alarm metrics with alarm details as labels
- Automatically refreshes the DCNM authentication token
- Configurable token expiration time

## Prerequisites

- Go 1.16 or higher
- Access to a Cisco Data Center Network Manager (DCNM) instance
- A Prometheus server to scrape the exported metrics

## Installation

1. Clone the repository:

```bash
git clone https://github.com/geekxflood/dcnm-alarms-exporter.git
```

2. Change to the project directory and build the binary:

```bash
cd dcnm-alarms-exporter
go build
```

## Usage

1. Set the following environment variables with the appropriate values for your DCNM instance:

```bash
export DCNM_URL=https://<dcnm-ip-or-hostname>:<port>
export DCNM_USERNAME=<your-username>
export DCNM_PASSWORD=<your-password>
export DCNM_EXPIRATION_TIME=<token-expiration-time-in-milliseconds>
```

**Note**: The DCNM_EXPIRATION_TIME should be greater than or equal to 5 minutes (300000 milliseconds).

2. Run the exporter:

```bash
./dcnm-exporter
```

3. Configure your Prometheus server to scrape the metrics from the exporter. Add the following lines to your prometheus.yml file:

```yaml
scrape_configs:
  - job_name: 'dcnm_alarms_exporter'
    static_configs:
      - targets: ['<exporter-ip-or-hostname>:9740']
```

Replace `<exporter-ip-or-hostname>` with the IP address or hostname of the machine running the exporter.

4. Reload your Prometheus configuration and start monitoring the DCNM alarms.

## Metrics

- `dcnm_ongoing_alarms`: Total number of ongoing alarms
- `dcnm_alarm`: Individual alarm metrics with the following labels:
  - `deviceName`
  - `deviceAttributes`
  - `message`
  - `lastScanTimeStamp`
  - `eventSwitch`
  - `eventType`
  - `description`
  - `severity`
