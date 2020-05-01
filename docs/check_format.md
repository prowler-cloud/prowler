# Check Format Definition & Features

This is a first pass at documenting the various features of the yaml check definition
specification.

Checks are broke into four logical sections:
1. Static Data
1. Call Definition
1. Post Process
1. Rule Definitions

## Static Data

This is the simplest part of the check. This includes various static items that get defined
for every check. By convention this comes first in the file (but that's not enforced).

```yaml
check_id: "1.9"
check_title: "Ensure IAM password policy requires minimum length of 14 or greater (Scored)"
check_alts:
  - CCE-78907-3
check_groups:
  - cis
  - cis=>level1
  - cis=>section1
  - cis_scored
  - ciscontrol=>16
  - ciscontrol=>16.12
  - ciscontrolv6=>5
  - ciscontrolv6=>5.7
  - ciscontrolv6=>16
  - ciscontrolv6=>16.12
platform: aws
regions:
  - "us-east-1"
```

* `check_id` : String that acts as a unique key
* `check_title` : A longer definition of the check. This should be the CIS check Name.
* `check_alts` : A list of alternative ways to reference this check (currently unused).
* `check_groups` : A list of groups that this check falls into. By default I've been categorizing checks
  as checks with a cis grouping, wich checks are cis_scored and by their ciscontrols (and their version 6)
  CIS controls. That may be overkill. I've been utilizing `=>` as a logical "in group" seperator.
* `platform` : Currently only `aws` supported and the directive is ignored but in theory in the
  future this may have `gcp` or `azure` or `k8s` and then "do the right thing" to do the check instead
  of using boto3.
* `regions` : Can be `all` as a string or a list of regions that the check should be ran against. Currently
  only AWS is supported but a similar concept is likely mappable from other future platforms.

## Call Section

This section defines how to get the data from the api that will be used to evaluate against. Belowe is
a simplistic call : 

```yaml
call:
  name: iam
  action: get_account_password_policy
  kwargs: {}
  args: []
```

This call (because it's associated with `aws` above), tells the system to utilize the [`iam` client](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#client)
in boto3 and call the [`get_account_password_policy`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy)
function with no kwargs and no arguments. 

There are a significatn number of other options that can be used with call including:

* `pre_call` A call to make before the main call. Has a similar name/action/args/kwargs functionality and also
  allows a delay option. The results of the call get inserted at `pre_call_data` in the root object for future
  usage. Example : 
  
      pre_call:
        name: iam
        action: generate_credential_report
        kwargs: {}
        args: []
        delay: 10

* `take` If you don't want the whole object referenced. You can specify a jq style path "take" to do the audit
  against. This can simplify the rule section. Please note that a [pyjq.all](https://stedolan.github.io/jq/manual/#Builtinoperatorsandfunctions)
  is used to grab this section so it will often make sense to take an iterator of objects with this specification.
  Here's an example: 
  
      call:
        name: iam
        action: list_users
        args: []
        take: ".Users[]"

* `paginator` [boto3.client provides a default paginator](https://boto3.amazonaws.com/v1/documentation/api/latest/search.html?q=get_paginator&check_keywords=yes&area=default)
 for large objects returns. If you're making a check against something where there are generally greater than 100 results
 from the api you'll likely want to use a paginator. What this will do is create an empty list and for every item returned
 from the paginator [`extend`](https://docs.python.org/3.8/library/stdtypes.html#typesseq-common) the list with new items.
 The jq part of `paginator` like take is evaluated with an [pyjq.all](https://stedolan.github.io/jq/manual/#Builtinoperatorsandfunctions)
 so it again makes sense to chose an iterator (something ending in []) as your pagination definition.
 Example: 
 
      call:
        name: ec2
        action: describe_instances
        args: []
        paginator: ".Reservations[].Instances[]"
  
* `fo_def` or "Fan Out Definitions". Some things need more than one call to collect the required data about an item. Often
  times with a rest api you'll collect information about a list of items and then *for each list* make a second call and
  "fan out" to get a full picture. This snippet allows you to do such a thing. Do keep in mind that fan out does make the
  assumption that your data is formatted as a "list of dicts". Which means that it doesn't work too well with `pre_call`
  (although some features in rule can make it work.)
  but does work pretty well with `take` and `paginator` (with `paginator` being referenced below).
  fo_def itself is a list of defintions. Each defintion with an object similar to `call`. There's a couple of differences
  though. First, each entry get's an `inname` item. This defines what the returned data will get stored as in the parent
  dictionary. And second is that `args` and `kwargs` accept [Jinja2 formatting](https://palletsprojects.com/p/jinja/) with
  the parent dict exposed as referenceable items. This allows you to utilize bits from the parent dictionary when makign the
  child call. Example:
  
      call:
        name: iam
        action: list_policies
        paginator: .Policies[]
        fo_def:
          - name: iam
            inname: list_entities_for_policy
            action: list_entities_for_policy
            kwargs:
              PolicyArn: "{{ Arn }}"
              
## Post Process

The big difference between post processed data and the call data is that the post proces data
is not cached and is recalulated on every one. The primary use case that drives the post process data
is the ability to turn base64 csv data to an actualy csv.DictReader style list of dictionaries.
The output of post_process get's stored as `post_process` on the main chunk of data.

Currently the only supported workflow is one that turns an AWS api formatted CSV string into one of these
lists of dicts. Example below:

```yaml
post_process:
  - type: bcsv
    field: ".Content"
    name: csv_report
```

## Rule Definitions

This is the meat of the system. What this does is defines a chain of conditions which must all be true
or trueish in order to pass. The important thing to remember is that you're defining how the data you just
called **should** look (as opposed to how it should not look). Itself a rule can be broken into three parts

1. Rule Conststants
1. Item (Target) Definitions
1. Comparisons

### Rule Constants

These are pretty simple. There's essentially three `name`, `pass_reason` and `fail_reason`. Name
gives a `name` for the rule. `pass_reason` gives a justification for why the check passed.
`fail_reason` gives a default reason for why the check failed. It should be noted that `fail_reason`
can (and likely should) be overwritten in each comparison with more detailed failure reason.

### Item (Target) Definitions

* `jqone` (exclusive with `jqiter`) allows you to specify a jq style path to the one item that will
  be used for evaluation. This uses the same formatting for subject as `jqiter` so you'll still need
  to define a `target_strategy` or you'll get the default "Not Specified" subject. But things like
  `target_jq`, `target_regex` and `target_noregex` don't make sense in that context and are not 
  evaulated. Example:
  
  
      item:
        jqone: .result.PasswordPolicy
        target_strategy:
          subject_const: "Account Password Policy"

* `jqiter` (exclusive with `jqone`) allows you to iterate through your call object in some fashion
  (also uses a [pyjq.all](https://stedolan.github.io/jq/manual/#Builtinoperatorsandfunctions) so return
  an array). This has the most complex target strategy. You'll want to use a `target_strategy` of `jqregex`
  (the default if not specified) or `all` and specify which items you've iterated through you wish to keep
  and which you wish to ignore.
  
      item:
        jqiter: .post_process.csv_report[]
        target_strategy:
          target_jq: .password_enabled
          target_regex: "true"
          subject_jq: .arn

* *Subjects* whether using `jqone` or `jqiter` you shoudl define a subject. It's considered best practice that
  if your call returns an arn to use it as your subject. But sometimes that's not the case. You can utilize
  `subject_jq` to pull back one item from the object to use as a subject. You can use `subject_const` to provide
  a static string that will get used as a subjec. If not specified, you'll get "Not Specified" as a default subject
  for each check. Examples:
  
      item:
        jqone: .result.PasswordPolicy
        target_strategy:
          subject_const: "Account Password Policy"
      ... or ...
      item: 
        jqiter: .post_process.csv_report[]
        target_strategy:
          target_jq: .user
          target_regex: "<root_account>"
          subject_jq: .arn
  
* `target_strategy` most impacful when used in conjunction with `jqiter`, target strategy defines which of the objects
  being evaluated should actually be evaluated and how each one should be referenced (using the subject above). You can
  use two main strategy types (`strat_types`) `jqregex` the assumed default and `all`. JQ Regex will allow you
  to pull an object out fo the potential target using jq and evaluate it against a regex for matching
  or not matching your desired outcome (using `target_regex` or `target_noregex`). If it matches (or with `target_noregex`
  fails to match) the regex specified it will be used on the comparison strategy below. Here are some examples:
  
      # Target Strategy with jqone
      item:
        jqone: .result.PasswordPolicy
        target_strategy:
          subject_const: "Account Password Policy"
      # Target Strategy JQRegex
      item:
        jqiter: .post_process.csv_report[]
        target_strategy:
          target_jq: .password_enabled
          target_regex: "true"
          subject_jq: .arn
      # Target Strategy All
      item:
        jqiter: .result[]
        target_strategy:
          subject_jq: .Arn
          strat_type: all

* `include_const` Say your call has some constant piece of data that's relevant (like a `pre_call_data`) and
  you wish to evaluate each target with that also available to you. You can utilize `include_const` in
  your definition and "stich" that constant data into your object at a particular name. Do keep in mind that
  if you have a lot of items each one will get a copy of the data. Example:
  
      item:
        jqone: .result.SummaryMap
        target_strategy:
          subject_const: Root MFA Strategy
          include_const:
            - pre_call_data: ".pre_call_data"
         
### Comparisons

This is the meat. The other section "chop up" your data to make it ready for comparisons. In comparisons you create
a "chain" of checks, all of which must pass in order for the check to return a pass for each item. A basic check looks
like this:

```yaml
compare:
  - comp_jq: .RequireSymbols
    rematch: "true"
    fail_reason: Account wide Password Policy Doesn't require Symbols
```

In this one you have a `comp_jq` item that defines which part of the item should be evaluated against. There's a default
`type` which in this example is `str` that will cast whatever is returned from jq as a string (more on types below). Then pictured
is a `rematch` object which defines a regex that the string pulled from `comp_jq` should match in order to pass (there's
also a `renomatch` directive which does the opposite). Finally you have a fail_reason which will get returned as the reason
for failing the check if the system fails at this checkpoint.

Now let's go into more options.

* `type` The type that should be assumed. Can be `str` (the assumed default), `int` or `time`. `str` and `int` niavely cast
  the result to that python datatype and throw an error if it experiences an error. `time` as a type requires a `time_format`
  definition that has a [Time Format String](https://docs.python.org/3/library/datetime.html#strftime-and-strptime-format-codes)
  that defines what `comp_jq` item should be defined as. It stores it as a unix timestamp for comparison.
* *Match Types* Each match type works with it's specified type. Here they are with definitions below. Only one can
  be used per object.
    * `time_older` (`type:time`). Takes an integer that represents how many seconds old the item should be older than.
    
          - comp_jq: .password_last_used
            type: time
            time_format: "%Y-%m-%dT%H:%M:%S+00:00"
            time_older: 7776000
            fail_reason: Root's Password was used in Last 90 Days
              
    * `time_newer` (`type:time`). Takes an integer that represents how many seconds old the item should be newer than.
    
          - comp_jq: .user_creation_time
            type: time
            time_format: "%Y-%m-%dT%H:%M:%S+00:00"
            time_newer: 7776000
            fail_reason: Access Key 2 never used on an Account over 90 Days Old. .
    
    * `rematch` & `renomatch` (`type:str`). A regex that the `comp_jq` should or should not match. See the "simple" example
      for a `rematch` directive.
   
    * `ge`, `le` and `eq` (`type:int`) `>=`, `<=` or `==` a particular specified number.
    
          - comp_jq: '.get_policy_version.PolicyVersion.Document  | [ .Statement[]| select(((.Effect == "Allow") and .Action == "*" ) and .Resource == "*") | add ] | length'
            type: "int"
            eq: 0
            fail_reason: Policy Allows Improperly Action * to *

Now that you can write a list of comparisons youc an also create trees of failure or passes using
`subpasscompare`  or `subfailcompare`. Essentially these are single compare dictionary's with the
same syntax that override the above pass or failure result. This allows you to do things like say, "Access
key 1 should be enabled (pass) and it should have been cycled in the last 90 days (fail) but if it
wasn't cycled in the last 90 days it should be less than 90 days old." Each `subpasscompare` or `subfailcompare` can
iteslf have chains for `subpasscompare` & `subfailcompare` results that it recursively travels through.

Here's a common style example from check 1.4 : 

```yaml
- comp_jq: .access_key_1_active
  renomatch: "true"
  subfailcompare:
    comp_jq: .access_key_1_last_rotated
    rematch: "N/A"
    subpasscompare:
      comp_jq: .user_creation_time
      type: time
      time_format: "%Y-%m-%dT%H:%M:%S+00:00"
      time_newer: 7776000
      fail_reason: Access Key 1 never Rotated on an Account over 90 Days Old.
    subfailcompare:
      comp_jq: .access_key_1_last_rotated
      type: time
      time_format: "%Y-%m-%dT%H:%M:%S+00:00"
      time_newer: 7776000
      fail_reason: Access Key 1 Not Rotated in the Last 90 Days
```

The above checks to see if access key one is active, by default it's saying that the right thing
is that access key 1 should not be active (`renomatch: "true"`). If that's the case it passes this check.
But if it is active it would normally fail. But because of `subfailcompare` instead the result of `subfailcompare`
will take over to see if things are good. `subfailcompare` asserts that the last rotate date equals `N/A`
and then catches both a pass *and* a failure with `subpasscompare` and `subfailcompare` being evaluated
on the same check. If last rotated date is `N/A` `subpasscompare` will fail you if you're users creation time
is older than 90 days (by asserting that you're newer than 90 days). If you have a rotated date, the `subfailcompare`
will check to make sure that your rotation date has occurred in the last 90 days.

And that's essentially how the system works.

