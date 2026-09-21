<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

// Fixtures se nacitaji rucne, aby testy bezely i po `composer install --no-dev`
// bez dumpu autoloadu; jsou to jen implementace rozhrani, ktere jinak dodava projekt.
$_fixtures = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__ . '/Fixtures'));
$_files = [];
foreach ($_fixtures as $_file) {
	if ($_file->isFile() && $_file->getExtension() === 'php') {
		$_files[] = $_file->getPathname();
	}
}
sort($_files);
foreach ($_files as $_file) {
	require_once $_file;
}

Tester\Environment::setup();
Tester\Environment::setupFunctions();
