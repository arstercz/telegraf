# Flume Input Plugin

The `flume` input plugin allows you to collect metrics from Apache Flume by querying its monitoring interface.

### Prerequisites

Before using this plugin, ensure that Flume is started with the `-Dflume.monitoring.port=34545` startup parameter. This
parameter is required to expose the Flume metrics for collection.

### Configuration

To use the Flume input plugin, you need to configure the following parameters:

- urls (required): A list of Flume monitoring URLs to query.
- job_name (required): The name of the Flume job being monitored.
- response_timeout (optional): Timeout for the HTTP requests made to Flume (default: 5s).

```toml
[[inputs.flume]]
  ## List of Flume monitoring URLs to query.
  urls = ["http://flume-monitoring-url1:34545", "http://flume-monitoring-url2:34545"]

  ## Name of the Flume job being monitored.
  job = "my_flume_job"

  ## Timeout for HTTP requests made to Flume (default: 5s).
  # response_timeout = "5s"
```

#### example_option

A more in depth description of an option can be provided here, but only do so if the option cannot be fully described in
the sample config.

### Metrics

The Flume input plugin retrieves various metrics from the Flume instance being monitored. The specific metrics and
fields depend on your Flume configuration and setup. Please refer to the Flume documentation for details on available
metrics and their meanings.

- flume
    - tags:
        - job
        - name
        - server
        - type
    - fields:
        - ChannelCapacity
        - ChannelSize
        - KafkaEventSendTimer
        - RollbackCount
        - EventReceivedCount
        - EventTakeAttemptCount
        - EventAcceptedCount
        - BatchUnderflowCount
        - AppendAcceptedCount
        - ConnectionCreatedCount
        - StartTime
        - ChannelWriteFail
        - GenericProcessingFail
        - StopTime
        - EventTakeSuccessCount
        - AppendReceivedCount
        - EventPutAttemptCount
        - EventDrainAttemptCount
        - ConnectionFailedCount
        - ChannelFillPercentage
        - EventPutSuccessCount
        - OpenConnectionCount
        - AppendBatchAcceptedCount
        - EventReadFail
        - BatchEmptyCount
        - BatchCompleteCount
        - AppendBatchReceivedCount
        - ConnectionClosedCount
        - EventDrainSuccessCount

### Example Output

```
flume,job=my_flume_job,host=testhost,name=c1,server=flume-monitoring-url1:34545,type=CHANNEL ChannelCapacity=1000,ChannelFillPercentage=0,ChannelSize=0,EventPutAttemptCount=0,EventPutSuccessCount=0,EventTakeAttemptCount=19182,EventTakeSuccessCount=0,StartTime=1689061980009,StopTime=0 1689215426000000000
flume,job=my_flume_job,host=testhost,name=s1,server=flume-monitoring-url1:34545,type=SINK BatchCompleteCount=0,BatchEmptyCount=19181,BatchUnderflowCount=0,ConnectionClosedCount=0,ConnectionCreatedCount=0,ConnectionFailedCount=0,EventDrainAttemptCount=0,EventDrainSuccessCount=0,KafkaEventSendTimer=0,RollbackCount=0,StartTime=1689061980684,StopTime=0 1689215426000000000
flume,job=my_flume_job,host=testhost,name=r1,server=flume-monitoring-url1:34545,type=SOURCE AppendAcceptedCount=0,AppendBatchAcceptedCount=0,AppendBatchReceivedCount=0,AppendReceivedCount=0,ChannelWriteFail=0,EventAcceptedCount=0,EventReadFail=0,EventReceivedCount=0,GenericProcessingFail=0,OpenConnectionCount=0,StartTime=1689061980555,StopTime=0 1689215426000000000
```
