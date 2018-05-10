#!/bin/env php
<?php

$configArgument = $argv[1];
$configPath     = getConfigPath($configArgument);

$config = readConfigFromPath($configPath);

foreach ($config['create'] as $createConfig) {
    callAndCreateCert(array(
        'domain'    => $createConfig['domain'],
        'directory' => $createConfig['directory'],
    ));
}
echo requestCertificate($config['request']);

function getConfigPath($configArgument) {
    $configPath = $configArgument;
    $isAbs      = ($configPath[0] === "/");
    if (false === $isAbs) {
        $configPath = sprintf('%s/%s', getcwd(), $configPath);
    }
    return $configPath;
}

function readConfigFromPath($configPath) {
    return json_decode(file_get_contents($configPath), true);
}

function callAndCreateCert($domainDetails) {
    $domain           = $domainDetails['domain'];
    $domainDirectory  = $domainDetails['directory'];
    $output           = authorizeDomain($domain);
    $authorizeDetails = parseAuthorizeOutput($output);
    writeChallengeFile($domainDirectory, $authorizeDetails['challenge-file'], $authorizeDetails['challenge-contents']);
    checkDomain($domain);
}

function authorizeDomain($domain) {
    $cmd = sprintf('acme authorize %s', $domain);
    return shell_exec($cmd);
}

function parseAuthorizeOutput($output) {
    $return  = array();
    $pattern = '/\.well-known\/acme-challenge\/(\S+)\n.*?content:\s+(\S+)/m';
    preg_match($pattern, $output, $matches);
    $return['challenge-file']     = $matches[1];
    $return['challenge-contents'] = $matches[2];
    unset($matches);
    return $return;
}

function writeChallengeFile($domainDirectory, $file, $contents) {
    $challengeDirectory = sprintf('%s/.well-known/acme-challenge/', rtrim($domainDirectory, '/'));
    if (false === file_exists($challengeDirectory)) {
        mkdir($challengeDirectory, 0777, true);
    }
    $filePath = sprintf('%s/%s', rtrim($challengeDirectory, '/'), $file);
    file_put_contents($filePath, $contents);
}

function checkDomain($domain) {
    $cmd = sprintf('acme check -s http %s', $domain);
    shell_exec($cmd);
}

function requestCertificate($domains) {
    $domainPartCmd = implode(' -a ', $domains);
    $cmd           = sprintf('acme request %s --force', $domainPartCmd);
    return shell_exec($cmd);
}
