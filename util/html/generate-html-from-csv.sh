#!/usr/bin/env bash

# Prowler - the handy cloud security tool (copyright 2020) by Toni de la Fuente
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.


## This script helps to generate a single html report from a single or multiple csv 
# output reports.
# I use it when I want to visualize multiple accounts reports in a single view.
# Report information and Assessment Summary will be empty due to the variables 
# that are not set here.

## First: Remove the CSV header from each output report.

## Second: If you want to aggretate all csv files in you can do like this: 
# find . -type f -name '*.csv' -exec cat {} + > prowler-output-unified-csv.file
# use .file instead of .csv unless you want to get into an infinite loop ;)

## Third: Usage ./generate-html-from-csv.sh aggregated-reports-csv.file


OUTPUT_FILE_NAME="report-unified-csv"
EXTENSION_HTML="html"
INPUT=$1
IFS=',' # used inside the while loop for csv delimiter 
HTML_LOGO_URL="https://github.com/toniblyx/prowler/"
HTML_LOGO_IMG="https://raw.githubusercontent.com/toniblyx/prowler/master/util/html/prowler-logo.png"


[ ! -f $INPUT ] && { echo "$INPUT file not found"; exit 99; }

addHtmlHeader() {
  if [[ $PROFILE == "" ]];then
    PROFILE="ENV"
  fi
  if [[ -z $HTML_REPORT_INIT ]]; then 
  cat <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <!-- Required meta tags -->
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <!-- Bootstrap CSS -->
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css" integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk" crossorigin="anonymous">
  <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.21/b-1.6.2/sl-1.3.1/datatables.min.css"/>
  <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.10.0/css/all.css" integrity="sha384-AYmEC3Yw5cVb3ZcuHtOA93w35dYTsvhLPVnYs9eStHfGJvOvKxVfELGroGkvsg+p" crossorigin="anonymous"/>
  <script type="text/javascript" src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js" integrity="sha384-OgVRvuATP1z7JjHLkuOU7Xw704+h835Lr+6QL9UvYjZE3Ipu6Tp75j7Bh/kR0JKI" crossorigin="anonymous"></script>
  <script type="text/javascript" src="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.21/b-1.6.2/sl-1.3.1/datatables.min.js"></script>
  <title>Prowler - AWS Security Assesments</title>
</head>
<body>
  <nav class="navbar navbar-expand-xl sticky-top navbar-dark bg-dark">
      <a class="navbar-brand" href="#">Prowler - Security Assesments in AWS</a>
  </nav>
  <div class="container-fluid">
    <div class="row mt-3">
      <div class="col-md-4">
        <div class="card">
          <div class="card-header">
            Report Information
          </div>
          <ul class="list-group list-group-flush">
            <li class="list-group-item">
              <div class="row">
                <div class="col-md-auto">
                  <b>Version:</b> $PROWLER_VERSION
                </div>
              </div>
            </li>
            <li class="list-group-item">
              <b>Parameters used:</b> $PROWLER_PARAMETERS
            </li>
            <li class="list-group-item">
              <b>Date:</b> $TIMESTAMP
            </li>
            <li class="list-group-item">
              <a href="$HTML_LOGO_URL"><img src="$HTML_LOGO_IMG"
                  alt="prowler-logo"></a>
            </li>
          </ul>
        </div>
      </div>
      <div class="col-md-8">
        <div class="card">
          <div class="card-header">
            Assesment Summary
          </div>
          <ul class="list-group list-group-flush">
            <li class="list-group-item">
              <b>AWS Account:</b> $ACCOUNT_NUM
            </li>
            <li class="list-group-item">
              <b>AWS-CLI Profile:</b> $PROFILE
            </li>
            <li class="list-group-item">
              <b>API Region:</b> $REGION
            </li>
            <li class="list-group-item">
              <b>User Id:</b> $USER_ID
            </li>
            <li class="list-group-item">
              <b>Caller Identity ARN:</b> $CALLER_ARN
            </li>
          </ul>
        </div>
        * Sortable columns are CheckID (default) and Result 
      </div>
    </div>
    <div class="row mt-3">
      <div class="col-md-12">
        <table class="table compact stripe row-border ordering" id="findingsTable" data-order='[[ 5, "asc" ]]' data-page-length='100'>
          <thead class="thead-light">
            <tr>
              <th style="align-content:center" scope="col">Status</th>
              <th scope="col">Result</th>
              <th scope="col">Severity</th>
              <th scope="col">AccountID</th>
              <th scope="col">Region</th>
              <th scope="col">Compliance</th>
              <th scope="col">Service</th>
              <th scope="col">CheckID</th>
              <th style="width:40%" scope="col">Check Title</th>
              <th style="width:40%" scope="col">Check Output</th>
            </tr>
          </thead>
          <tbody>
EOF

fi 
}

addHtmlFooter() {
  cat <<EOF

</tbody>
        </table>
      </div>
    </div>
  </div>
  </div>
  <!-- Table search and paginator -->
  <!-- Optional JavaScript -->
  <!-- jQuery first, then Popper.js, then Bootstrap JS -->
  <script src="https://code.jquery.com/jquery-3.5.1.min.js" integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0=" crossorigin="anonymous"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.bundle.min.js" integrity="sha384-1CmrxMRARb6aLqgBO7yyAxTOQE2AKb9GfXnEo760AUcUmFx3ibVJJAzGytlQcNXd" crossorigin="anonymous"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js" integrity="sha384-OgVRvuATP1z7JjHLkuOU7Xw704+h835Lr+6QL9UvYjZE3Ipu6Tp75j7Bh/kR0JKI" crossorigin="anonymous"></script>
  <!-- JQuery-->
  <script src="https://code.jquery.com/jquery-3.5.1.min.js" integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0=" crossorigin="anonymous"></script>
  <!-- dataTables-->
  <script src="https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js"></script>
  <script>
    \$(document).ready(function(){ \$('#findingsTable').dataTable( { "lengthMenu": [ [50, 100, -1], [50, 100, "All"] ], "ordering": true } ); });
  </script>
</body>
</html>
EOF

unset HTML_REPORT_INIT
}

addHtmlHeader > ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
while IFS=, read -r PROFILE ACCOUNT_NUM REPREGION TITLE_ID RESULT SCORED LEVEL TITLE_TEXT NOTES ASFF_COMPLIANCE_TYPE CHECK_SEVERITY CHECK_SERVICENAME;do
  if [[ $RESULT == "INFO" ]]; then 
    echo '<tr class="table-info">' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td><i class="fas fa-info-circle"></i></td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>INFO</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$CHECK_SEVERITY'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$ACCOUNT_NUM'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$REPREGION'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$ASFF_COMPLIANCE_TYPE'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$CHECK_SERVICENAME'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$TITLE_ID'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$TITLE_TEXT'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$NOTES'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
    echo '</tr>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
  fi 
  if [[ $RESULT == "PASS" ]]; then 
    echo '<tr class="p-3 mb-2 bg-success">' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td><i class="fas fa-thumbs-up"></i></td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>PASS</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$CHECK_SEVERITY'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$ACCOUNT_NUM'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$REPREGION'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$ASFF_COMPLIANCE_TYPE'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$CHECK_SERVICENAME'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$TITLE_ID'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$TITLE_TEXT'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$NOTES'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
    echo '</tr>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
  fi 
  if [[ $RESULT == "FAIL" ]]; then 
    echo '<tr class="table-danger" >' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td> <i class="fas fa-thumbs-down"></i></td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>FAIL</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$CHECK_SEVERITY'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$ACCOUNT_NUM'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$REPREGION'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$ASFF_COMPLIANCE_TYPE'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$CHECK_SERVICENAME'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$TITLE_ID'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$TITLE_TEXT'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$NOTES'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
    echo '</tr>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
  fi
  if [[ $RESULT == "WARNING" ]]; then 
    echo '<tr class="table-warning">' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td><i class="fas fa-exclamation-triangle"></i></td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>WARN</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$CHECK_SEVERITY'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$ACCOUNT_NUM'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$REPREGION'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$ASFF_COMPLIANCE_TYPE'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$CHECK_SERVICENAME'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$TITLE_ID'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$TITLE_TEXT'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
      echo '<td>'$NOTES'</td>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
    echo '</tr>' >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML
  fi
done < $INPUT
addHtmlFooter >> ${OUTPUT_FILE_NAME}.$EXTENSION_HTML



