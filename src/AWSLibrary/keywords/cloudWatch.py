from AWSLibrary.librarycomponent import LibraryComponent
from robot.api.deco import keyword
from robot.api import logger
from datetime import datetime, timedelta
import time
import re


class CloudWatchKeywords(LibraryComponent):

    def __init__(self, library):
        LibraryComponent.__init__(self, library)
        self.endpoint_url = None

    @keyword('CloudWatch Set Endpoint Url')
    def cloudwatch_set_endpoint(self, url):
        """ The complete URL to use for the constructed CloudWatch client. Normally, botocore will automatically construct the
        appropriate URL to use when communicating with a service. You can specify a complete URL
        (including the “http/https” scheme) to override this behavior.

        | =Arguments= | =Description= |
        | ``url`` | <str> The complete endpoint URL. |

        *Examples:*
        | CloudWatch Set Endpoint Url | http://localhost:4566/ |
        """
        self.endpoint_url = url

    @keyword('CloudWatch Logs Insights')
    def insights_query(self, log_group, query, start_time=60):
        """Executes a query on CloudWatch Insights and return the found results in a list.

        | =Arguments= | =Description= |
        | ``log_group`` | <str> Log group name. |
        | ``query`` | <str> Aws query log format. |
        | ``start_time`` | <str> The beginning of the time range to query from now to ago in minutes. |

        ---
        Use the same aws console ``query`` format in the argument, like this examples:

        - Filter only by a part of the message, return the timestamp and the message:
        | ``fields @timestamp, @message | filter @message like 'some string inside message to search' | sort @timestamp desc | limit 5``
        - Filter by json path and part of the message, return only the message:
        | ``fields @message | filter API.httpMethod = 'GET' and @message like 'Zp8beEeByQ0EDvg' | sort @timestamp desc | limit 20``
        - Find the 10 most expensive requests:
        | ``filter @type = "REPORT" | fields @requestId, @billedDuration | sort by @billedDuration desc | limit 10``

        For more information, see CloudWatch Logs Insights Query Syntax.
        https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html
        ---

        *Examples:*
        | ${logs} | CloudWatch Logs Insights | /aws/group-name | query |
        | ${logs} | CloudWatch Logs Insights | /aws/group-name | query | start_time=120 |
        """
        client = self.library.session.client('logs', endpoint_url=self.endpoint_url)
        time_behind = (datetime.now() - timedelta(minutes=start_time)).timestamp()
        query = client.start_query(logGroupName=log_group,
                                   startTime=int(time_behind),
                                   endTime=int(datetime.now().timestamp()),
                                   queryString=query)
        query_id = query['queryId']
        response = client.get_query_results(queryId=query_id)
        while response['status'] == 'Running':
            logger.debug("waiting for Logs Insights")
            time.sleep(0.5)
            response = client.get_query_results(queryId=query_id)
        results = [sublist[1:] for sublist in response['results']]
        return results

    # ------------------------------------------------------------------
    # Advanced Insights keyword: absolute time window, full result rows,
    # queryId/statistics passback, configurable timeout, multi-account
    # CloudTrail pattern support.
    # ------------------------------------------------------------------

    @keyword('CloudWatch Logs Insights Query')
    def insights_query_advanced(
        self,
        log_group,
        query,
        start_epoch=None,
        end_epoch=None,
        start_time=60,
        timeout=120,
        poll_interval=2,
        return_metadata=False,
        log_group_names=None,
    ):
        """Execute a CloudWatch Logs Insights query with absolute time windows and full result metadata.

        This keyword extends `CloudWatch Logs Insights` with:

        - Absolute epoch-second timestamps (``start_epoch`` / ``end_epoch``) so you
          can target specific investigation windows instead of only "N minutes ago".
        - A configurable ``timeout`` to avoid tests hanging on large scans.
        - A configurable ``poll_interval`` to tune cost vs. latency.
        - Optional ``return_metadata`` flag that returns a dictionary with
          ``results``, ``queryId``, and ``statistics`` for cost/scan visibility.
        - Optional ``log_group_names`` list for multi-log-group queries (e.g.
          querying a consolidated organization CloudTrail log group alongside
          VPC Flow Logs in a single call).

        *Consolidated payer-account CloudTrail pattern* — the recommended AWS
        Organizations best practice is to enable organization-level CloudTrail
        with a single destination log group in the management (payer) account
        (e.g. ``/aws/cloudtrail/org``). All member-account events land in one
        place, avoiding per-account session switching. Set ``LOG_GROUP_NAME``
        (or pass ``log_group``) to the payer account log group and filter by
        ``recipientAccountId`` inside the query to scope to individual accounts:

        | ``fields @timestamp, recipientAccountId, userIdentity.arn, eventName``
        | ``| filter recipientAccountId = "123456789012"``
        | ``| sort @timestamp desc | limit 50``

        | =Arguments= | =Description= |
        | ``log_group`` | <str> Primary log group name. |
        | ``query`` | <str> CloudWatch Logs Insights query string. |
        | ``start_epoch`` | <int|None> Query start as Unix epoch seconds. Overrides ``start_time`` when set. |
        | ``end_epoch`` | <int|None> Query end as Unix epoch seconds. Defaults to now when ``start_epoch`` is set. |
        | ``start_time`` | <int> Minutes-ago fallback used when ``start_epoch`` is None (default: 60). |
        | ``timeout`` | <int> Seconds to wait for query completion before raising (default: 120). |
        | ``poll_interval`` | <float> Seconds between poll attempts (default: 2). |
        | ``return_metadata`` | <bool> When True returns ``{results, queryId, statistics}`` instead of a plain list (default: False). |
        | ``log_group_names`` | <list|None> Additional log group names for cross-log-group queries (default: None). |

        ---
        *Examples:*

        Simple relative window (behaves like `CloudWatch Logs Insights`):
        | ${rows} | CloudWatch Logs Insights Query | /aws/cloudtrail/org | fields @timestamp, eventName \\| limit 20 |

        Absolute investigation window:
        | ${start}= | Evaluate | int(time.mktime(time.strptime("2026-08-01", "%Y-%m-%d"))) | modules=time
        | ${end}= | Evaluate | int(time.mktime(time.strptime("2026-08-31", "%Y-%m-%d"))) | modules=time
        | ${rows} | CloudWatch Logs Insights Query | /aws/cloudtrail/org | fields @timestamp, eventName \\| limit 20 | start_epoch=${start} | end_epoch=${end} |

        Multi-log-group cross-account query:
        | ${rows} | CloudWatch Logs Insights Query | /aws/cloudtrail/org | fields @timestamp, eventName \\| limit 20 | log_group_names=["/aws/vpc/flowlogs"] |

        Return queryId and scan statistics:
        | ${meta} | CloudWatch Logs Insights Query | /aws/cloudtrail/org | fields @timestamp \\| limit 1 | return_metadata=${True} |
        | Log | Query ID: ${meta['queryId']} |
        | Log | Scanned bytes: ${meta['statistics']['bytesScanned']} |
        """
        client = self.library.session.client('logs', endpoint_url=self.endpoint_url)

        if start_epoch is not None:
            t_start = int(start_epoch)
            t_end = int(end_epoch) if end_epoch is not None else int(datetime.now().timestamp())
        else:
            t_start = int((datetime.now() - timedelta(minutes=int(start_time))).timestamp())
            t_end = int(datetime.now().timestamp())

        params = {
            'logGroupName': log_group,
            'startTime': t_start,
            'endTime': t_end,
            'queryString': query,
        }
        if log_group_names:
            params['logGroupNames'] = list(log_group_names)

        resp = client.start_query(**params)
        query_id = resp['queryId']
        logger.info(f"CloudWatch Logs Insights Query started: queryId={query_id}")

        deadline = time.time() + float(timeout)
        response = None
        while time.time() < deadline:
            response = client.get_query_results(queryId=query_id)
            status = response['status']
            logger.debug(f"CloudWatch Logs Insights Query status={status}")
            if status in ('Complete', 'Failed', 'Cancelled', 'Timeout'):
                break
            time.sleep(float(poll_interval))
        else:
            raise TimeoutError(
                f"CloudWatch Logs Insights query {query_id} did not complete within {timeout}s "
                f"(last status: {response['status'] if response else 'unknown'})"
            )

        if response['status'] != 'Complete':
            raise RuntimeError(
                f"CloudWatch Logs Insights query {query_id} ended with status={response['status']}"
            )

        rows = response.get('results', [])
        statistics = response.get('statistics', {})
        logger.info(
            f"CloudWatch Logs Insights Query complete: queryId={query_id} "
            f"rows={len(rows)} scannedBytes={statistics.get('bytesScanned', 'n/a')}"
        )

        if return_metadata:
            return {
                'results': rows,
                'queryId': query_id,
                'statistics': statistics,
            }
        return rows

    @keyword('CloudWatch Wait For Logs')
    def wait_for_logs(self, log_group, filter_pattern, regex_pattern, seconds_behind=60, timeout=30,
                      not_found_fail=False):
        """Wait until find the wanted log in cloudwatch.

        This keyword is used to wait in real time if the desired log appears inside the informed log group.
        It works in a similar way to the existing CloudWatch filter in "Live Tail".

        Return all the logs that match the informed regex in a list.

        | =Arguments= | =Description= |
        | ``log_group`` | <str> Log group name. |
        | ``filter_pattern`` | <str> Filter for CloudWatch. |
        | ``regex_pattern`` | <str> Regex pattern to search in filter results. |
        | ``seconds_behind`` | <str> How many seconds from now to ago, used to searching the logs. |
        | ``timeout`` | <str> Timeout in seconds to end the search. |
        | ``not_found_fail`` | <bool> If set as True, the keyword will fail if not find any log |

        ---
        For ``filter_pattern`` use the same as aws console filter patterns in Live tail.
        https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html

        - Filter for json path in log:
        | {$.foo.bar = some_string_value}
        - Filter for json path with null value in log:
        | {$.foo.bar IS NULL}
        - Filter for INFO logs:
        | INFO
        - Filter for DEBUG logs:
        | DEBUG
        - Filter for anything in logs:
        | " "

        For ``regex_pattern`` use the same regular expressions that robot framework uses in BuildIn Library.
        ---

        Note: as boto3 takes some time to get the logs and apply the regex query to each one of them, depending on the
        amount of log found, the keyword execution time may be slightly longer than the timeout.

        *Examples:*
        | ${logs} | CloudWatch Wait For Logs | /aws/group_name | {$.foo.bar = id_value} | 2024.*filename |
        | ${logs} | CloudWatch Wait For Logs | /aws/group_name | INFO | code.*id_code | timeout=60 |
        | ${logs} | CloudWatch Wait For Logs | /aws/group_name | " " | code.*some_code | not_found_fail=${True} |
        """
        client = self.library.session.client('logs', endpoint_url=self.endpoint_url)
        stream_response = client.describe_log_streams(logGroupName=log_group,
                                                      orderBy='LastEventTime',
                                                      descending=True,
                                                      limit=1)
        latest_log_stream_name = stream_response["logStreams"][0]["logStreamName"]
        logger.info("The latest stream is: %s" % latest_log_stream_name)
        stream_response = client.describe_log_streams(logGroupName=log_group,
                                                      logStreamNamePrefix=latest_log_stream_name)
        logger.debug(stream_response)
        last_event = stream_response['logStreams'][0]['lastIngestionTime']
        logger.info("Last event: %s" % datetime.fromtimestamp(int(last_event) / 1000).strftime('%d-%m-%Y %H:%M:%S'))
        last_event_delay = last_event - seconds_behind * 1000
        logger.info("Starting the log search from: %s" % datetime.fromtimestamp(int(last_event_delay) / 1000)
                    .strftime('%d-%m-%Y %H:%M:%S'))
        events_match = []
        for i in range(int(timeout)):
            response = client.filter_log_events(logGroupName=log_group,
                                                startTime=last_event_delay,
                                                filterPattern=filter_pattern)
            logger.info("%s Total records found" % len(response["events"]))
            logger.debug(response["events"])
            for event in response["events"]:
                match_event = re.search(regex_pattern, event['message'])
                if match_event:
                    events_match.append(event['message'])
            if len(events_match) > 0:
                break
            else:
                time.sleep(1)
        if not_found_fail and len(events_match) == 0:
            raise Exception(f"Log not found in CloudWatch inside {log_group} for {filter_pattern} and {regex_pattern}")
        return events_match
