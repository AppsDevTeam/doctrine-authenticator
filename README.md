# Doctrine Authenticator

- Allows you to use a Doctrine entity as a Nette identity
- Uses cookies instead of PHP sessions
- Saves IP address and User-Agent header for better abuse detection
- Detects an invalid token and call onInvalidToken callback to log and prevent possible abuse
- Invalidates token on different User-Agent header and IP address when fraudDetection is enabled and call onFraudDetection callback to log and prevent possible abuse

## Install

```
composer require adt/doctrine-authenticator
```

## Configuration

### 1) Neon configuration

```neon
services:
	security.user: App\Model\Security\SecurityUser
	security.userStorage: Nette\Bridges\SecurityHttp\CookieStorage
	security.authenticator:
		factory: App\Model\Security\Authenticator(expiration: '14 days')
		setup:
			- setFraudDetection(true) # you can disable it for automatic tests for example
			- setAuthLog(true) # operational auth_log table, see "Auth log" below
```

Add new mapping via attributes like this (if you are using nettrine):

```neon
nettrine.orm.attributes:
	mapping:
		ADT\DoctrineAuthenticator: %appDir%/../vendor/adt/doctrine-authenticator/src
```

or via annotations:

```neon
nettrine.orm.annotations:
	mapping:
		ADT\DoctrineAuthenticator: %appDir%/../vendor/adt/doctrine-authenticator/src
```

### 2) Create a Identity entity implementing ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity

and adjust to your needs.

```php
<?php

namespace App\Model\Entities;

use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\GeneratedValue;
use Doctrine\ORM\Mapping\Id;

/** @Entity */
#[Entity]
class Identity implements DoctrineAuthenticatorIdentity
{
	/**
	 * @Id
	 * @Column
	 * @GeneratedValue
	 */
	#[Id]
	#[Column]
	#[GeneratedValue]
	protected ?int $id;

	public function getId(): int
	{
		return $this->id;
	}

	public function __clone()
	{
		$this->id = null;
	}
	


	/** @Column(unique=true) */
	#[Column(unique: true)]
	protected string $email;

	/** @Column */
	#[Column]
	protected string $password;

	public function getEmail(): string
	{
		return $this->email;
	}

	public function setEmail(string $email): self
	{
		$this->email = $email;
		return $this;
	}

	public function getPassword(): string
	{
		return $this->password;
	}

	public function setPassword(string $password): self
	{
		$this->password = $password;
		return $this;
	}

	
	
	public function getRoles(): array
	{
		return [];
	}

	public function getAuthObjectId(): string
	{
		return (string) $this->getId();
	}
}
```

### 3) Create a SecurityUser service extending ADT\DoctrineAuthenticator\SecurityUser

```php
<?php

namespace App\Model\Security;

use App\Model\Entities\Identity;

/**
 * @method Identity getIdentity()
 */
class SecurityUser extends \ADT\DoctrineAuthenticator\SecurityUser
{

}
```

### 4) Create Authenticator extending ADT\DoctrineAuthenticator\DoctrineAuthenticator

and adjust methods `authenticate` and `getIdentity` to your needs. 

```php
<?php

namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use App\Model\Entities\Identity;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManagerInterface;
use Nette\Bridges\SecurityHttp\CookieStorage;
use Nette\Http\Request;
use Nette\Security\AuthenticationException;
use Nette\Security\IIdentity;
use Nette\Security\Passwords;

class Authenticator extends DoctrineAuthenticator
{
	public function __construct(
		string $expiration,
		CookieStorage $cookieStorage,
		Connection $connection,
		Configuration $configuration,
		Request $httpRequest,
		protected readonly EntityManagerInterface $em,
	) {
		parent::__construct($expiration, $cookieStorage, $connection, $configuration, $httpRequest);
		
		$this->onInvalidToken = function(string $token) {
			// log probable fraud
		};
	}

	public function authenticate(string $user, string $password): IIdentity
	{
		/** @var Identity $identity */
		if (! $identity = $this->em->getRepository(Identity::class)->findOneBy(['email' => $user])) {
			throw new AuthenticationException('Identity not found!');
		}

		if (!(new Passwords())->verify($password, $identity->getPassword())) {
			throw new AuthenticationException('Incorrect password!');
		}

		return $identity;
	}

	public function getIdentity($id): IIdentity
	{
		return $this->em->getRepository(Identity::class)->find($id);
	}
}
```

### 5) Generate migrations

for example like this:

```bash
php bin/console migrations:diff
```

## Usage

Just call `login` on security user as you are used to:

```php
$this->securityUser->login($email, $password);
```

## Country-based fraud detection

The default fraud detection kills a session when both the IP and the
User-Agent change at once. An attacker who stole the session token can
trivially copy the User-Agent, so you can additionally bind the session to
a country: any IP change within one country is allowed (mobile networks,
CGNAT), moving to a different country kills the session even with a matching
User-Agent.

```neon
setup:
    - setCountryFraudDetection('/geoip/GeoLite2-Country.mmdb')
```

Requires `composer require geoip2/geoip2` and a MaxMind Country database.
The recommended way to provide and refresh the `.mmdb` file is the official
[geoipupdate](https://github.com/maxmind/geoipupdate) container writing into
a volume mounted read-only into the application container (MaxMind licensing
does not allow bundling the file, and it goes stale - updates are published
twice a week).

The check fails open: an unresolvable IP or a missing/unreadable database
never kills a session, it only disables the country rule (the IP+User-Agent
rule still applies). Detected frauds are recorded in the auth log with reason
`country changed (CZ -> US)`.

## Login attempt throttling

```neon
setup:
    - setLoginAttemptProtection(5, '-15 minutes', maxAccountAttempts: 10, maxSprayedAccounts: 20)
```

Upgrading an existing installation needs a migration - `login_attempt` gained
a `successful` column (default `0`, every existing row is a failure) and two
indexes on `username`.

Failed sign-ins are counted in `login_attempt` over a sliding window. Three
independent counters, because no single key covers both threat models:

| counter | argument | what it stops |
|---|---|---|
| (IP, account) | `$maxAttempts` | ordinary guessing from one address |
| account, all IPs | `$maxAccountAttempts` (default `2 * $maxAttempts`) | distributed guessing - rotating source IPs no longer buys a fresh budget against the same account (CWE-307) |
| distinct accounts per IP | `$maxSprayedAccounts` (default off) | password spraying, which neither counter above sees |

The first counter is deliberately narrower than a plain per-IP counter:
behind one NAT - a venue full of terminals, an office - a single mistyped
password must not lock out everybody sharing that address.

Spray detection would hit those same shared addresses, so its budget is not
a flat number: it is `$maxSprayedAccounts` **plus the number of accounts that
address has successfully signed in** within `$trustedIpPeriod`. A venue with
a hundred terminals therefore carries a budget of a hundred-odd on its own,
while an address an attacker rented this morning gets the bare
`$maxSprayedAccounts` - no hand-kept IP whitelist to go stale.

Note it counts accounts *failed* on, so a venue signing in normally never
moves the counter at all, however many terminals it has.

### Known-good addresses

An account-wide counter makes a targeted lockout DoS possible - anyone who
knows an email address can burn that account's budget. It is blunted by
remembering where the account has successfully signed in from: a successful
sign-in stores a `successful` row for the pair (IP, account), kept for
`$trustedIpPeriod` (30 days). For such a pair:

- the account-wide counter does not apply at all
- the (IP, account) budget is multiplied by `$trustedIpMultiplier` (4)

So a legitimate user on a machine they have used before keeps getting in
while an attacker elsewhere is stopped. Nothing locks an account
persistently - every counter is a sliding window, and a successful sign-in
clears that account's failed attempts, so a few typos are never carried over
into the next sign-in.

The marker row is refreshed in place, so a pair costs one row however often
it signs in, and markers past `$trustedIpPeriod` are dropped on the way.

Rejected attempts are recorded too (for the audit trail) but never counted -
otherwise each blocked request would move the window and keep the account
locked out for as long as the requests keep coming. Blocked attempts surface
in the auth log as `login_blocked`.

## Auth log (operational)

With `setAuthLog(true)` the authenticator records every authentication event in
the `auth_log` table:

| type | when |
|---|---|
| `login` | successful login (written in the same transaction as the session row) |
| `login_failed` | failed login - records the entered identity and the exception class |
| `login_blocked` | attempt rejected by the login-attempt protection |
| `logout` | session invalidated via `clearIdentity()` / `clearSession()` |
| `fraud_detected` | session killed because IP and User-Agent both changed |
| `invalid_token` | cookie token not found (metadata contains its sha256 for correlation with `session.token`) |

Rows are inserted through the DBAL connection (no ORM events, no unit of work)
and are never updated. Passwords or other credentials are never recorded. Times
are always in UTC, so the records line up with other logs.

**This is an operational log, not an audit trail.** It answers "who signed in,
when and from where" for support and diagnostics, and it is meant to be readable
from the project's admin. An audit trail has to live outside the application, so
that nobody who reaches the application can rewrite the record of what they did
there - build that separately from `$onAuthEvent`.

Having both is a deliberate choice, not an accident: two copies of the same event
with different retention and a different set of readers. Just make sure the
project's logging policy says so - a document claiming audit records are
unreachable from the application is not true of this table.

The table grows until someone prunes it; retention is up to the project.

## Clearing expired sessions

Register the extension, which registers the console command:

```neon
extensions:
	doctrineAuthenticator: ADT\DoctrineAuthenticator\DI\DoctrineAuthenticatorExtension
```

It deletes sessions whose `validUntil` is older than the given number of days
(defaults to 365 days, i.e. one year):

```bash
# delete sessions expired more than a year ago (default)
php bin/console doctrine-authenticator:clear-expired-sessions

# delete sessions expired more than 30 days ago
php bin/console doctrine-authenticator:clear-expired-sessions 30
```

Run it periodically (e.g. via cron) to keep the `session` table clean.
