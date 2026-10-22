<?php

declare(strict_types=1);

$path = $argv[1] ?? dirname(__DIR__).'/build/coverage.xml';
libxml_use_internal_errors(true);
$report = is_file($path) ? simplexml_load_file($path) : false;
if ($report === false || ! isset($report->project->metrics)) {
    fwrite(STDERR, "A valid Clover coverage report is required.\n");
    exit(1);
}
$statements = (int) $report->project->metrics['statements'];
$covered = (int) $report->project->metrics['coveredstatements'];
if ($statements < 1 || $covered < 0 || $covered > $statements) {
    fwrite(STDERR, "Coverage report has invalid statement counts.\n");
    exit(1);
}
$percentage = $covered / $statements * 100;
printf("Source line coverage: %.2f%% (required: 90%%).\n", $percentage);
exit($percentage >= 90 ? 0 : 1);
