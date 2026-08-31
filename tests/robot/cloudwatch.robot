*** Settings ***
Resource    common.resource
Suite Setup    Create Session And Set Endpoint
Suite Teardown    Delete All Sessions


*** Variables ***
${LOG_GROUP}      test


*** Test Cases ***
Test Wait For Log
    [Tags]    cloudwatch
    [Setup]    keywords.Send Cloudwatch Message    Hello From CloudWatch
    ${logs}    CloudWatch Wait For Logs    ${LOG_GROUP}    " "    Hello.*Watch    timeout=10
    Should Not Be Empty    ${logs}
    Should Contain    ${logs}[0]    Hello From CloudWatch

Test Log Insights
    [Tags]    cloudwatch
    [Setup]    keywords.Send Cloudwatch Message    Hello From CloudWatch
    Sleep    30s    #You need to wait for the log to be indexed in cloudwatch for the query to work
    ${query}    Set Variable    fields @message | filter @message like 'Hello' | sort @timestamp desc | limit 10
    ${logs}    CloudWatch Logs Insights    ${LOG_GROUP}    ${query}
    Should Not Be Empty    ${logs}

Test Log Insights Query - Relative Window
    [Documentation]    CloudWatch Logs Insights Query keyword: relative window (default start_time=60m).
    [Tags]    cloudwatch
    [Setup]    keywords.Send Cloudwatch Message    Hello From CloudWatch Insights Query
    Sleep    30s
    ${query}    Set Variable    fields @message | filter @message like 'Hello' | sort @timestamp desc | limit 10
    ${rows}    CloudWatch Logs Insights Query    ${LOG_GROUP}    ${query}
    Should Not Be Empty    ${rows}

Test Log Insights Query - Absolute Window
    [Documentation]    CloudWatch Logs Insights Query keyword: absolute epoch start/end.
    [Tags]    cloudwatch
    [Setup]    keywords.Send Cloudwatch Message    Hello Absolute Window
    Sleep    30s
    ${start}=    Evaluate    int(time.time()) - 300    modules=time
    ${end}=    Evaluate    int(time.time())    modules=time
    ${query}    Set Variable    fields @message | filter @message like 'Hello' | limit 10
    ${rows}    CloudWatch Logs Insights Query    ${LOG_GROUP}    ${query}    start_epoch=${start}    end_epoch=${end}
    Should Not Be Empty    ${rows}

Test Log Insights Query - Return Metadata
    [Documentation]    CloudWatch Logs Insights Query keyword: return_metadata exposes queryId and statistics.
    [Tags]    cloudwatch
    [Setup]    keywords.Send Cloudwatch Message    Hello Metadata Test
    Sleep    30s
    ${query}    Set Variable    fields @message | limit 1
    ${meta}    CloudWatch Logs Insights Query    ${LOG_GROUP}    ${query}    return_metadata=${True}
    Dictionary Should Contain Key    ${meta}    queryId
    Dictionary Should Contain Key    ${meta}    statistics
    Dictionary Should Contain Key    ${meta}    results
    Should Not Be Empty    ${meta}[queryId]
