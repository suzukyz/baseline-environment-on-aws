import * as cdk from 'aws-cdk-lib';
import { aws_iam as iam } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { aws_config as config } from 'aws-cdk-lib';
import { aws_sns as sns } from 'aws-cdk-lib';
import { aws_cloudwatch as cw } from 'aws-cdk-lib';
import { aws_cloudwatch_actions as cwa } from 'aws-cdk-lib';
import { aws_events as cwe } from 'aws-cdk-lib';
import { aws_logs as cwl } from 'aws-cdk-lib';
import { aws_events_targets as cwet } from 'aws-cdk-lib';
import { ITopic } from 'aws-cdk-lib/aws-sns';

interface MetricGenerationStrategy {
  createMetricsAndAlarms(scope: Construct, topic: ITopic): void;
}

// This class is used in case of parameter.additionalTrail is true.
class CloudTrailMetricStrategy implements MetricGenerationStrategy {
  constructor(private readonly logGroup: cwl.ILogGroup) {}
  
  createMetricsAndAlarms(scope: Construct, topic: ITopic): void {
    // IAM Policy Change
    this.createMetricFilterAndAlarm(
      scope,
      'IAMPolicyChange',
      {
        logPatternString: '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}',
      },
      'CloudTrailMetrics',
      'IAMPolicyEventCount',
      '1',
      {
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 1,
        alarmDescription: 'IAM Configuration changes detected!',
      },
      topic
    );
    
    // Unauthorized Attempts
    this.createMetricFilterAndAlarm(
      scope,
      'UnauthorizedAttempts',
      {
        logPatternString: '{($.errorCode = "*UnauthorizedOperation" || $.errorCode = "AccessDenied*") && ($.eventName != "Decrypt" || $.userIdentity.invokedBy != "config.amazonaws.com" )}',
      },
      'CloudTrailMetrics',
      'UnauthorizedAttemptsEventCount',
      '1',
      {
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 5,
        alarmDescription: 'Multiple unauthorized actions or logins attempted!',
      },
      topic
    );
    
    // New Access Key Created
    this.createMetricFilterAndAlarm(
      scope,
      'NewAccessKeyCreated',
      {
        logPatternString: '{($.eventName=CreateAccessKey)}',
      },
      'CloudTrailMetrics',
      'NewAccessKeyCreatedEventCount',
      '1',
      {
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 1,
        alarmDescription: 'Warning: New IAM access key was created. Please be sure this action was necessary.',
      },
      topic
    );
    
    // Root User Activity
    this.createMetricFilterAndAlarm(
      scope,
      'RootUserActivity',
      {
        logPatternString: '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}',
      },
      'CloudTrailMetrics',
      'RootUserPolicyEventCount',
      '1',
      {
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 1,
        alarmDescription: 'Root user activity detected!',
      },
      topic
    );
  }
  
  private createMetricFilterAndAlarm(
    scope: Construct,
    id: string,
    filterPattern: cwl.IFilterPattern,
    metricNamespace: string,
    metricName: string,
    metricValue: string,
    alarmProps: {
      evaluationPeriods: number;
      datapointsToAlarm: number;
      threshold: number;
      alarmDescription: string;
    },
    topic: ITopic
  ): void {
    const metricFilter = new cwl.MetricFilter(scope, `${id}Filter`, {
      logGroup: this.logGroup,
      filterPattern: filterPattern,
      metricNamespace: metricNamespace,
      metricName: metricName,
      metricValue: metricValue,
    });
    
    new cw.Alarm(scope, `${id}Alarm`, {
      metric: metricFilter.metric({
        period: cdk.Duration.seconds(300),
        statistic: cw.Stats.SUM,
      }),
      evaluationPeriods: alarmProps.evaluationPeriods,
      datapointsToAlarm: alarmProps.datapointsToAlarm,
      threshold: alarmProps.threshold,
      comparisonOperator: cw.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription: alarmProps.alarmDescription,
      actionsEnabled: true,
    }).addAlarmAction(new cwa.SnsAction(topic));
  }
}

// This class is used in case of parameter.additionalTrail is false.
class EventBridgeMetricStrategy implements MetricGenerationStrategy {
  createMetricsAndAlarms(scope: Construct, topic: ITopic): void {
    // IAM Policy Change
    this.createEventRuleWithMetricAndAlarm(
      scope,
      'IAMPolicyChange',
      'Notify to change on IAM policy',
      {
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventSource: ['iam.amazonaws.com'],
          eventName: ['DeleteGroupPolicy', 'DeleteRolePolicy', 'DeleteUserPolicy', 'PutGroupPolicy', 'PutRolePolicy', 'PutUserPolicy', 'CreatePolicy', 'DeletePolicy', 'CreatePolicyVersion', 'DeletePolicyVersion', 'AttachRolePolicy', 'DetachRolePolicy', 'AttachUserPolicy', 'DetachUserPolicy', 'AttachGroupPolicy', 'DetachGroupPolicy'],
        },
      },
      'CloudTrailMetrics',
      'IAMPolicyEventCount',
      {
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 1,
        alarmDescription: 'IAM Configuration changes detected!',
      },
      topic
    );
    
    // Unauthorized Attempts
    this.createEventRuleWithMetricAndAlarm(
      scope,
      'UnauthorizedAttempts',
      'Notify unauthorized operations',
      {
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          errorCode: [{ wildcard: '*UnauthorizedOperation' }, { wildcard: 'AccessDenied*' }],
          "$or": [
            { eventName: [{'anything-but': 'Decrypt' }]},
            { 
              userIdentity: {
                invokedBy: [{'anything-but': 'config.amazonaws.com' }]
              },
            }
          ]
        },
      },
      'CloudTrailMetrics',
      'UnauthorizedAttemptsEventCount',
      {
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 5,
        alarmDescription: 'Multiple unauthorized actions or logins attempted!',
      },
      topic
    );
    
    // New Access Key Created
    this.createEventRuleWithMetricAndAlarm(
      scope,
      'NewAccessKeyCreated',
      'Notify when a new IAM access key is created',
      {
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventSource: ['iam.amazonaws.com'],
          eventName: ['CreateAccessKey'],
        },
      },
      'CloudTrailMetrics',
      'NewAccessKeyCreatedEventCount',
      {
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 1,
        alarmDescription: 'Warning: New IAM access key was created. Please be sure this action was necessary.',
      },
      topic
    );
    
    // Root User Activity
    this.createEventRuleWithMetricAndAlarm(
      scope,
      'RootUserActivity',
      'Notify when root user activity is detected',
      {
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          userIdentity: {
            type: ['Root'],
            invokedBy: [{ exists: false }]
          },
          eventType: [{'anything-but': 'AwsServiceEvent'}]
        },
      },
      'CloudTrailMetrics',
      'RootUserPolicyEventCount',
      {
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 1,
        alarmDescription: 'Root user activity detected!',
      },
      topic
    );
  }
  
  private createEventRuleWithMetricAndAlarm(
    scope: Construct,
    id: string,
    description: string,
    eventPattern: cwe.EventPattern,
    metricNamespace: string,
    metricName: string,
    alarmProps: {
      evaluationPeriods: number;
      datapointsToAlarm: number;
      threshold: number;
      alarmDescription: string;
    },
    topic: ITopic
  ): void {
    
    // To call PutMetricData via AWS Lambda created by cdk of AwsApi construct
    const target = new cwet.AwsApi({
      action: 'PutMetricData',
      service: 'CloudWatch',
      parameters: {
        MetricData: [
          {
            MetricName: metricName,
            Dimensions: [
              {
                Name: "EventSource",
                Value: "EventBridge",
              },
            ],
            Unit: "None",
            Value: 1.0,
          },
        ],
        Namespace: metricNamespace,
      }
    });
    
    // Create EventBridge Rule
    new cwe.Rule(scope, `${id}EventRule`, {
      description: description,
      enabled: true,
      eventPattern: eventPattern,
      targets: [target]
    });
    
    // Create an Alarm that is based on metrics
    new cw.Alarm(scope, `${id}Alarm`, {
      metric: new cw.Metric({
        namespace: metricNamespace,
        metricName: metricName,
        dimensionsMap: {
          "EventSource": "EventBridge",
        },
      }),
      evaluationPeriods: alarmProps.evaluationPeriods,
      datapointsToAlarm: alarmProps.datapointsToAlarm,
      threshold: alarmProps.threshold,
      comparisonOperator: cw.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription: alarmProps.alarmDescription,
      actionsEnabled: true,
    }).addAlarmAction(new cwa.SnsAction(topic));
  }
}

class MetricStrategyFactory {
  static createStrategy(scope: Construct, additionalTrail: boolean, cloudTrailLogGroupName?: string): MetricGenerationStrategy {
    if (additionalTrail && cloudTrailLogGroupName) {
      const logGroup = cwl.LogGroup.fromLogGroupName(
        scope, 
        'CloudTrailLogGroup', 
        cloudTrailLogGroupName
      );
      return new CloudTrailMetricStrategy(logGroup);
    } else {
      return new EventBridgeMetricStrategy();
    }
  }
}

export interface DetectionProps {
  notifyEmail: string;
  cloudTrailLogGroupName?: string;
  additionalTrail?: boolean;
}

export class Detection extends Construct {
  public readonly topic: ITopic;

  constructor(scope: Construct, id: string, props: DetectionProps) {
    super(scope, id);

    // === AWS Config Rules ===
    // ConfigRule for Default Security Group is closed  (Same as SecurityHub - need this for auto remediation)
    //
    // See: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-4.3
    // See: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html
    const defaultSgClosedRule = new config.ManagedRule(this, 'DefaultSgClosedRule', {
      identifier: config.ManagedRuleIdentifiers.VPC_DEFAULT_SECURITY_GROUP_CLOSED,
      ruleScope: config.RuleScope.fromResources([config.ResourceType.EC2_SECURITY_GROUP]),
      configRuleName: 'bb-default-security-group-closed',
      description:
        'Checks that the default security group of any Amazon Virtual Private Cloud (VPC) does not allow inbound or outbound traffic. The rule is non-compliant if the default security group has one or more inbound or outbound traffic.',
    });

    // Role for auto remediation
    const defaultSgRemediationRole = new iam.Role(this, 'DefaultSgRemediationRole', {
      assumedBy: new iam.ServicePrincipal('ssm.amazonaws.com'),
      path: '/',
      managedPolicies: [{ managedPolicyArn: 'arn:aws:iam::aws:policy/service-role/AmazonSSMAutomationRole' }],
    });
    defaultSgRemediationRole.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['ec2:RevokeSecurityGroupIngress', 'ec2:RevokeSecurityGroupEgress', 'ec2:DescribeSecurityGroups'],
        resources: ['*'],
      }),
    );
    defaultSgRemediationRole.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['iam:PassRole'],
        resources: [defaultSgRemediationRole.roleArn],
      }),
    );
    defaultSgRemediationRole.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['ssm:StartAutomationExecution'],
        resources: ['arn:aws:ssm:::automation-definition/AWSConfigRemediation-RemoveVPCDefaultSecurityGroupRules'],
      }),
    );

    // Remediation for Remove VPC Default SecurityGroup Rules  by  SSM Automation
    new config.CfnRemediationConfiguration(this, 'DefaultSgRemediation', {
      configRuleName: defaultSgClosedRule.configRuleName,
      targetType: 'SSM_DOCUMENT',
      targetId: 'AWSConfigRemediation-RemoveVPCDefaultSecurityGroupRules',
      targetVersion: '1',
      parameters: {
        AutomationAssumeRole: {
          StaticValue: {
            Values: [defaultSgRemediationRole.roleArn],
          },
        },
        GroupId: {
          ResourceValue: {
            Value: 'RESOURCE_ID',
          },
        },
      },
      automatic: true,
      maximumAutomaticAttempts: 5,
      retryAttemptSeconds: 60,
    });

    // SNS Topic for Security Alarm
    const topic = new sns.Topic(this, 'AlarmTopic');
    new sns.Subscription(this, 'SecurityAlarmEmail', {
      endpoint: props.notifyEmail,
      protocol: sns.SubscriptionProtocol.EMAIL,
      topic: topic,
    });
    cdk.Stack.of(this).exportValue(topic.topicArn);
    this.topic = topic;

    // Allow to publish message from CloudWatch
    topic.addToResourcePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('cloudwatch.amazonaws.com')],
        actions: ['sns:Publish'],
        resources: [topic.topicArn],
      }),
    );

    // --------------- ConfigRule Compliance Change Notification -----------------
    // ConfigRule - Compliance Change
    //  See: https://docs.aws.amazon.com/config/latest/developerguide/monitor-config-with-cloudwatchevents.html
    //  See: https://aws.amazon.com/premiumsupport/knowledge-center/config-resource-non-compliant/?nc1=h_ls
    //  If you want to add rules to notify, add rule name text string to "configRuleName" array.
    //  Sample Rule 'bb-default-security-group-closed' is defined at lib/blea-config-rules-stack.ts
    new cwe.Rule(this, 'DefaultSgClosedEventRule', {
      description: 'CloudWatch Event Rule to send notification on Config Rule compliance changes.',
      enabled: true,
      eventPattern: {
        source: ['aws.config'],
        detailType: ['Config Rules Compliance Change'],
        detail: {
          configRuleName: ['bb-default-security-group-closed'],
          newEvaluationResult: {
            complianceType: ['NON_COMPLIANT'],
          },
        },
      },
      targets: [new cwet.SnsTopic(topic)],
    });

    // ------------------------ AWS Health Notification ---------------------------

    // AWS Health - Notify any events on AWS Health
    // See: https://aws.amazon.com/premiumsupport/knowledge-center/cloudwatch-notification-scheduled-events/?nc1=h_ls
    new cwe.Rule(this, 'AwsHealthEventRule', {
      description: 'Notify AWS Health event',
      enabled: true,
      eventPattern: {
        source: ['aws.health'],
        detailType: ['AWS Health Event'],
      },
      targets: [new cwet.SnsTopic(topic)],
    });

    // ------------ Detective guardrails from NIST standard template ----------------
    // See: https://aws.amazon.com/blogs/publicsector/automating-compliance-architecting-for-fedramp-high-and-nist-workloads-in-aws-govcloud-us/

    // Security Groups Change Notification
    // See: https://aws.amazon.com/premiumsupport/knowledge-center/monitor-security-group-changes-ec2/?nc1=h_ls
    //  from NIST template
    new cwe.Rule(this, 'SgChangedEventRule', {
      description: 'Notify to create, update or delete a Security Group.',
      enabled: true,
      eventPattern: {
        source: ['aws.ec2'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventSource: ['ec2.amazonaws.com'],
          eventName: [
            'AuthorizeSecurityGroupIngress',
            'AuthorizeSecurityGroupEgress',
            'RevokeSecurityGroupIngress',
            'RevokeSecurityGroupEgress',
          ],
        },
      },
      targets: [new cwet.SnsTopic(topic)],
    });

    // Network ACL Change Notification
    //  from NIST template
    new cwe.Rule(this, 'NetworkAclChangeEventRule', {
      description: 'Notify to create, update or delete a Network ACL.',
      enabled: true,
      eventPattern: {
        source: ['aws.ec2'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventSource: ['ec2.amazonaws.com'],
          eventName: [
            'CreateNetworkAcl',
            'CreateNetworkAclEntry',
            'DeleteNetworkAcl',
            'DeleteNetworkAclEntry',
            'ReplaceNetworkAclEntry',
            'ReplaceNetworkAclAssociation',
          ],
        },
      },
      targets: [new cwet.SnsTopic(topic)],
    });

    // CloudTrail Change
    //  from NIST template
    new cwe.Rule(this, 'CloudTrailChangeEventRule', {
      description: 'Notify to change on CloudTrail log configuration',
      enabled: true,
      eventPattern: {
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventSource: ['cloudtrail.amazonaws.com'],
          eventName: ['StopLogging', 'DeleteTrail', 'UpdateTrail'],
        },
      },
      targets: [new cwet.SnsTopic(topic)],
    }); 

    // ------------------- Other security services integration ----------------------

    // SecurityHub - Imported
    //   Security Hub automatically sends all new findings and all updates to existing findings to EventBridge as Security Hub Findings - Imported events.
    //   See: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html
    //
    //   Security Hub Finding format
    //   See: https://docs.aws.amazon.com/ja_jp/securityhub/latest/userguide/securityhub-findings-format.html
    new cwe.Rule(this, 'SecurityHubEventRule', {
      description: 'CloudWatch Event Rule to send notification on SecurityHub all new findings and all updates.',
      enabled: true,
      eventPattern: {
        source: ['aws.securityhub'],
        detailType: ['Security Hub Findings - Imported'],
        detail: {
          findings: {
            Severity: {
              Label: ['CRITICAL', 'HIGH'],
            },
            Compliance: {
              Status: ['FAILED'],
            },
            Workflow: {
              Status: ['NEW', 'NOTIFIED'],
            },
            RecordState: ['ACTIVE'],
          },
        },
      },
      targets: [new cwet.SnsTopic(topic)],
    });

    // GuardDutyFindings
    //   Will alert for any Medium to Critical finding.
    //   See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_cloudwatch.html
    new cwe.Rule(this, 'GuardDutyEventRule', {
      description: 'CloudWatch Event Rule to send notification on GuardDuty findings.',
      enabled: true,
      eventPattern: {
        source: ['aws.guardduty'],
        detailType: ['GuardDuty Finding'],
        detail: {
          severity: [
            4, 4.0, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 5, 5.0, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 6,
            6.0, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 7, 7.0, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 8,
            8.0, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 9, 9.0, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 10,
            10.0,
          ],
        },
      },
      targets: [new cwet.SnsTopic(topic)],
    });

    // additionalTrailに基づいて戦略を選択し、メトリクスとアラームを作成
    const additionalTrail = props.additionalTrail !== undefined ? props.additionalTrail : true;
    const metricStrategy = MetricStrategyFactory.createStrategy(
      this,
      additionalTrail,
      props.cloudTrailLogGroupName
    );
    
    // 選択された戦略を使用してメトリクスとアラームを作成
    metricStrategy.createMetricsAndAlarms(this, topic);
  }
}
