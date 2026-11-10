<?php

declare(strict_types=1);

use ADT\DoctrineAuthenticator\OTP\OnetimeTokenService;
use ADT\DoctrineAuthenticator\OTP\OnetimeTokenTypeEnum;
use ADT\DoctrineAuthenticator\Tests\Entity\TestOtpUser;
use ADT\DoctrineAuthenticator\Tests\TestAuthenticator;
use ADT\DoctrineAuthenticator\Tests\TestOnetimeTokenAuthenticator;
use Nette\Security\AuthenticationException;
use Nette\Security\Passwords;
use Tester\Assert;

/**
 * Jednorazovy token v poli heslo prihlasi jen identitu, ktere patri.
 *
 * findToken() s identifikatorem najde i tokeny bez identifikatoru (pozvanka, obnova hesla,
 * "prihlasit se jako"). Bez kontroly vlastnika tak token kohokoli, treba z vlastni registrace,
 * fungoval jako heslo k libovolnemu e-mailu.
 */

require __DIR__ . '/bootstrap.php';

$dbFile = tempnam(sys_get_temp_dir(), 'otp') . '.sqlite';
register_shutdown_function(fn() => @unlink($dbFile));

$em = TestAuthenticator::createEntityManagerOn($dbFile, [__DIR__ . '/Fixtures/Entity']);
$attacker = new TestOtpUser('attacker@example.com', new Passwords()->hash('attacker-password'));
$victim = new TestOtpUser('victim@example.com', new Passwords()->hash('victim-password'));
$em->persist($attacker);
$em->persist($victim);
$em->flush();

$tokens = new OnetimeTokenService($em);
$authenticator = new TestOnetimeTokenAuthenticator($em);
$validUntil = new DateTimeImmutable('+1 hour');

test('heslo prihlasi svou identitu bez tokenu', function () use ($authenticator, $victim) {
	$identity = $authenticator->authenticate('victim@example.com', 'victim-password');

	Assert::same($victim, $identity);
	Assert::null($identity->getOnetimeToken());
});

test('token bez identifikatoru nefunguje jako heslo k cizimu e-mailu', function () use ($authenticator, $tokens, $attacker, $validUntil) {
	$token = $tokens->saveToken(OnetimeTokenTypeEnum::LOGIN, $validUntil, $attacker, checkLimit: false);

	Assert::exception(
		fn() => $authenticator->authenticate('victim@example.com', $token),
		AuthenticationException::class,
	);
});

test('token s identifikatorem ciziho e-mailu nefunguje jako heslo k cizimu e-mailu', function () use ($authenticator, $tokens, $attacker, $validUntil) {
	$token = $tokens->saveToken(OnetimeTokenTypeEnum::LOGIN, $validUntil, $attacker, identifier: 'victim@example.com', checkLimit: false);

	Assert::exception(
		fn() => $authenticator->authenticate('victim@example.com', $token),
		AuthenticationException::class,
	);
});

test('vlastni token funguje jako heslo', function () use ($authenticator, $tokens, $victim, $validUntil) {
	$token = $tokens->saveToken(OnetimeTokenTypeEnum::LOGIN, $validUntil, $victim, identifier: 'victim@example.com', checkLimit: false);

	$identity = $authenticator->authenticate('victim@example.com', $token);

	Assert::same($victim, $identity);
	Assert::same($victim->getId(), $identity->getOnetimeToken()?->getObjectId());
});

test('token bez vlastnika nefunguje jako heslo', function () use ($authenticator, $tokens, $validUntil) {
	$token = $tokens->saveToken(OnetimeTokenTypeEnum::LOGIN, $validUntil, identifier: 'victim@example.com', checkLimit: false);

	Assert::exception(
		fn() => $authenticator->authenticate('victim@example.com', $token),
		AuthenticationException::class,
	);
});

test('token z odkazu prihlasi svou identitu', function () use ($authenticator, $tokens, $attacker, $validUntil) {
	$token = $tokens->saveToken(OnetimeTokenTypeEnum::LOGIN, $validUntil, $attacker, checkLimit: false);

	Assert::same($attacker, $authenticator->authenticate($token));
});
