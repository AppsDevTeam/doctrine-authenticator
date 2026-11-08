<?php

declare(strict_types=1);

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use ADT\DoctrineAuthenticator\Tests\Entity\TestUser;
use ADT\DoctrineAuthenticator\Tests\TestAuthenticator;
use Nette\Security\SimpleIdentity;
use Tester\Assert;

/**
 * Platny token se pri kazdem pozadavku neprepisuje.
 *
 * wakeupIdentity() posouvala platnost tokenu (klouzava expirace) pri kazdem pozadavku - tedy
 * zapis do `session` u kazdeho AJAXu a pollingu, na Galere replikovany na vsechny uzly, jen aby
 * se platnost posunula o par sekund. Posouva se proto az o TOKEN_REFRESH_INTERVAL a vic.
 */

require __DIR__ . '/bootstrap.php';


$dbFile = tempnam(sys_get_temp_dir(), 'refresh') . '.sqlite';
register_shutdown_function(fn() => @unlink($dbFile));
$entityDirs = [__DIR__ . '/Fixtures/Entity'];

$em = TestAuthenticator::createEntityManagerOn($dbFile, $entityDirs);
$em->persist(new TestUser('u1'));
$em->flush();

$token = new TestAuthenticator($em)->sleepIdentity(new TestUser('u1'))->getId();
$connection = $em->getConnection();
$column = $em->getClassMetadata(ADT\DoctrineAuthenticator\StorageEntity::class)->getColumnName('validUntil');

/** Dalsi pozadavek: novy EntityManager i autentizator, jen databaze je stejna */
$wakeup = function () use ($dbFile, $entityDirs, $token): void {
	$authenticator = new TestAuthenticator(TestAuthenticator::createEntityManagerOn($dbFile, $entityDirs, createSchema: false));
	Assert::type(TestUser::class, $authenticator->wakeupIdentity(new SimpleIdentity($token)));
};
$setValidUntil = fn(string $time) => $connection->executeStatement("UPDATE session SET $column = ?", [new DateTimeImmutable($time)->format('Y-m-d H:i:s')]);
$validUntil = fn(): DateTimeImmutable => new DateTimeImmutable($connection->fetchOne("SELECT $column FROM session"));


test('token, ktery by se posunul o mene nez interval, se neprepise', function () use ($wakeup, $setValidUntil, $validUntil) {
	$almostFull = '+14 days -' . (DoctrineAuthenticator::TOKEN_REFRESH_INTERVAL / 2) . ' seconds';
	$setValidUntil($almostFull);
	$before = $validUntil();

	$wakeup();

	Assert::equal($before, $validUntil());
});


test('starsi token se posune na plnou platnost', function () use ($wakeup, $setValidUntil, $validUntil) {
	$setValidUntil('+1 day');

	$wakeup();

	Assert::true($validUntil() > new DateTimeImmutable('+13 days'));
});
