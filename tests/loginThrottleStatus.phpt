<?php

declare(strict_types=1);

use ADT\DoctrineAuthenticator\TooManyLoginAttemptsException;
use ADT\DoctrineAuthenticator\Tests\TestAuthenticator;
use Nette\Security\AuthenticationException;
use Tester\Assert;
use Tester\FileMock;

/**
 * Co getLoginThrottleStatus() hlasi uzivateli.
 *
 * TooManyLoginAttemptsException dedi z AuthenticationException, takze prihlasovaci formular,
 * ktery chytal rodice, ukazal po vycerpani pokusu tutez vetu jako pri prvnim prekleplem
 * hesle: uzivatel nevedel, ze je zablokovany, ani do kdy, a sel s tim na podporu.
 *
 * Testuje se to spolu se skutecnym blokovanim, protoze ta cisla maji cenu jen potud, pokud
 * odpovidaji tomu, co se opravdu vynucuje - jinak hlaska slibuje pokus, ktery uz neexistuje.
 */

require __DIR__ . '/bootstrap.php';


const MAX_PAIR_ATTEMPTS = 5;
const MAX_ACCOUNT_ATTEMPTS = 10;
const MAX_SPRAYED_ACCOUNTS = 4;
const TIMEOUT = '-15 minutes';

const ACCOUNT = 'user@example.com';
const WRONG_PASSWORD = 'nope';


function authenticator(): TestAuthenticator
{
	// Kazdy test dostava cistou databazi - pokusy z predchoziho by mu ujidaly limit.
	$dbFile = tempnam(sys_get_temp_dir(), 'throttle') . '.sqlite';
	register_shutdown_function(fn() => @unlink($dbFile));

	$authenticator = new TestAuthenticator(TestAuthenticator::createEntityManagerOn($dbFile));
	$authenticator->setLoginAttemptProtection(
		MAX_PAIR_ATTEMPTS,
		TIMEOUT,
		maxAccountAttempts: MAX_ACCOUNT_ATTEMPTS,
		maxSprayedAccounts: MAX_SPRAYED_ACCOUNTS,
	);

	return $authenticator;
}


/**
 * Pokus, ktery ma projit throttlingem a spadnout az na hesle. Kontrola na
 * AuthenticationException by zamek nepoznala, protoze z ni dedi - proto presna trida.
 */
function expectRejectedNotThrottled(TestAuthenticator $authenticator, string $ip, string $username, string $message): void
{
	try {
		$authenticator->attempt($ip, $username, WRONG_PASSWORD);
	} catch (TooManyLoginAttemptsException) {
		Assert::fail($message);
	} catch (AuthenticationException) {
		return;
	}

	Assert::fail('spatne heslo musi byt odmitnuto: ' . $username);
}


test('odpocet dojde na nulu prave tim pokusem, kterym throttling zaklapne', function () {
	// O jedna vedle znamena bud slib pokusu, ktery uz neni, nebo blokaci ohlasenou driv,
	// nez nastane - obojí posle uzivatele na podporu stejne jako puvodni stav.
	$authenticator = authenticator();
	$ip = '192.0.2.70';

	Assert::same(MAX_PAIR_ATTEMPTS, $authenticator->status($ip, ACCOUNT)->remainingAttempts);

	for ($i = 1; $i <= MAX_PAIR_ATTEMPTS; $i++) {
		expectRejectedNotThrottled($authenticator, $ip, ACCOUNT, 'parovy limit je ' . MAX_PAIR_ATTEMPTS . ' pokusu');

		Assert::same(
			MAX_PAIR_ATTEMPTS - $i,
			$authenticator->status($ip, ACCOUNT)->remainingAttempts,
			'po ' . $i . '. neuspechu',
		);
	}

	Assert::true($authenticator->status($ip, ACCOUNT)->isBlocked());
	Assert::exception(
		fn() => $authenticator->attempt($ip, ACCOUNT, WRONG_PASSWORD),
		TooManyLoginAttemptsException::class,
	);
});


test('dokud limit vycerpany neni, blokace se nehlasi', function () {
	$authenticator = authenticator();
	$ip = '192.0.2.71';

	for ($i = 1; $i < MAX_PAIR_ATTEMPTS; $i++) {
		expectRejectedNotThrottled($authenticator, $ip, ACCOUNT, 'limit jeste vycerpany neni');

		Assert::false($authenticator->status($ip, ACCOUNT)->isBlocked(), 'po ' . $i . '. neuspechu');
	}
});


test('cas odblokovani lezi v budoucnu a do delky okna', function () {
	// Driv by uzivatele vratil do blokace, pozdeji by ho nechal cekat zbytecne.
	$authenticator = authenticator();
	$ip = '192.0.2.72';

	for ($i = 0; $i < MAX_PAIR_ATTEMPTS; $i++) {
		expectRejectedNotThrottled($authenticator, $ip, ACCOUNT, 'vycerpani limitu');
	}

	$blockedUntil = $authenticator->status($ip, ACCOUNT)->blockedUntil;
	$now = new DateTimeImmutable();

	Assert::notSame(null, $blockedUntil);
	Assert::true($blockedUntil > $now);
	Assert::true($blockedUntil <= $now->modify('+15 minutes')->modify('+2 seconds'));
});


test('dalsi pokusy behem blokace cas odblokovani neodsunou', function () {
	// Okno je klouzave a uz zamitnute pokusy se do nej nepocitaji. Kdyby ho posouvaly,
	// ukazoval by uzivatel odpocet, ktery nikdy nedobehne, dokud utocnik klepe.
	$authenticator = authenticator();
	$ip = '192.0.2.73';

	for ($i = 0; $i < MAX_PAIR_ATTEMPTS; $i++) {
		expectRejectedNotThrottled($authenticator, $ip, ACCOUNT, 'vycerpani limitu');
	}

	$blockedUntil = $authenticator->status($ip, ACCOUNT)->blockedUntil;

	for ($i = 0; $i < 3; $i++) {
		Assert::exception(
			fn() => $authenticator->attempt($ip, ACCOUNT, WRONG_PASSWORD),
			TooManyLoginAttemptsException::class,
		);
	}

	Assert::equal($blockedUntil, $authenticator->status($ip, ACCOUNT)->blockedUntil);
});


test('ucetni limit napric adresami se hlasi stejne jako parovy', function () {
	// Jinak by uzivatel, kteremu nekdo jiny vycerpal ucetni limit, cetl nenulovy zbytek
	// a zkousel dal.
	$authenticator = authenticator();

	for ($i = 0; $i < MAX_ACCOUNT_ATTEMPTS; $i++) {
		expectRejectedNotThrottled($authenticator, '198.51.100.' . $i, ACCOUNT, 'ucetni limit je ' . MAX_ACCOUNT_ATTEMPTS);
	}

	$freshIp = '203.0.113.30';
	$status = $authenticator->status($freshIp, ACCOUNT);

	Assert::same(0, $status->remainingAttempts, 'cerstva adresa uz zadny pokus nema, i kdyz sama neselhala');
	Assert::true($status->isBlocked());
	Assert::exception(
		fn() => $authenticator->attempt($freshIp, ACCOUNT, WRONG_PASSWORD),
		TooManyLoginAttemptsException::class,
	);
});


test('spraying se hlasi jako blokace i uctu, na kterem se jeste neselhalo', function () {
	// Spray citac jsou ruzne ucty, ne pokusy proti tomuhle - dokud neblokuje, nema
	// k zbyvajicim pokusum co rict, a jakmile blokuje, musi byt zbytek nula.
	$authenticator = authenticator();
	$ip = '203.0.113.20';

	for ($i = 0; $i < MAX_SPRAYED_ACCOUNTS; $i++) {
		expectRejectedNotThrottled($authenticator, $ip, 'spray-' . $i . '@example.com', 'spray limit je ' . MAX_SPRAYED_ACCOUNTS . ' uctu');
	}

	$status = $authenticator->status($ip, ACCOUNT);

	Assert::same(0, $status->remainingAttempts);
	Assert::true($status->isBlocked());
	Assert::exception(
		fn() => $authenticator->attempt($ip, ACCOUNT, WRONG_PASSWORD),
		TooManyLoginAttemptsException::class,
	);
});


test('prokazane heslo vrati cely rozpocet', function () {
	// Par prekleplu se nesmi prenaset do dalsiho prihlaseni, jinak uzivatel zacina
	// s uz docerpanym limitem.
	$authenticator = authenticator();
	$ip = '192.0.2.74';

	for ($i = 0; $i < MAX_PAIR_ATTEMPTS - 1; $i++) {
		expectRejectedNotThrottled($authenticator, $ip, ACCOUNT, 'limit jeste vycerpany neni');
	}

	$authenticator->attempt($ip, ACCOUNT, TestAuthenticator::PASSWORD);

	$status = $authenticator->status($ip, ACCOUNT);

	// Adresa je nove duveryhodna, takze ma parovy limit nasobeny - hlasi se tedy vic nez
	// holy limit, ale rozhodne ne min.
	Assert::true($status->remainingAttempts >= MAX_PAIR_ATTEMPTS);
	Assert::false($status->isBlocked());
});


test('vypnuta brzda nehlasi nic', function () {
	// Formular pak nema co upresnit a necha puvodni obecnou hlasku.
	$authenticator = authenticator();
	$authenticator->setLoginAttemptProtection(0);

	$status = $authenticator->status('192.0.2.75', ACCOUNT);

	Assert::null($status->remainingAttempts);
	Assert::false($status->isBlocked());
});
