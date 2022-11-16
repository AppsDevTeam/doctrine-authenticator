# Doctrine Authenticator

Allows you to use a Doctrine entity as a Nette identity.

## Install

```
composer require adt/doctrine-authenticator
```

## Usage

```neon
services:
	security.user: App\Model\Security\SecurityUser
	security.userStorage: Nette\Bridges\SecurityHttp\CookieStorage
	security.authenticator: App\Model\Security\Authenticator('14 days')
```

```php
<?php

declare(strict_types=1);

namespace App\Model\Entities;

use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use ADT\DoctrineAuthenticator\DoctrineAuthenticatorSession;
use App\Model\Entities\Attributes;
use DateTimeImmutable;
use Exception;
use Doctrine\ORM\Mapping as ORM;

/** @ORM\Entity */
class Session implements DoctrineAuthenticatorSession
{
	use Attributes\Identifier;
	use Attributes\CreatedAt;

	/** @ORM\ManyToOne(targetEntity="Identity", inversedBy="sessions") */
	protected Identity $identity;

	/** @ORM\Column(type="string", length="32") */
	protected string $token;

	/** @ORM\Column(type="datetime_immutable", nullable=true) */
	protected ?DateTimeImmutable $validUntil = null;

	/** @ORM\Column(type="datetime_immutable", nullable=true) */
	protected ?DateTimeImmutable $regeneratedAt = null;

	/** @ORM\Column(type="string", nullable=false) */
	protected string $ip;

	/** @ORM\Column(type="string", nullable=false) */
	protected string $userAgent;

	public function __construct(Identity $identity, string $token)
	{
		$this->identity = $identity;
		$this->token = $token;
	}

	public function getIdentity(): Identity
	{
		return $this->identity;
	}

	public function getToken(): string
	{
		return $this->token;
	}

	public function setToken(string $token): self
	{
		$this->token = $token;
		return $this;
	}

	/**
	 * @throws Exception
	 */
	public function getAuthEntity(): DoctrineAuthenticatorIdentity
	{
		return $this->getIdentity();
	}

	public function getValidUntil(): ?DateTimeImmutable
	{
		return $this->validUntil;
	}

	public function setValidUntil(DateTimeImmutable $validUntil): self
	{
		$this->validUntil = $validUntil;
		return $this;
	}

	public function getRegeneratedAt(): ?DateTimeImmutable
	{
		return $this->regeneratedAt;
	}

	public function setRegeneratedAt(?DateTimeImmutable $regeneratedAt): self
	{
		$this->regeneratedAt = $regeneratedAt;
		return $this;
	}

	public function getIp(): string
	{
		return $this->ip;
	}

	public function setIp(string $ip): self
	{
		$this->ip = $ip;
		return $this;
	}

	public function getUserAgent(): string
	{
		return $this->userAgent;
	}

	public function setUserAgent(string $userAgent): self
	{
		$this->userAgent = $userAgent;
		return $this;
	}
}

```

```php
<?php

namespace App\Model\Entities;

use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use App\Model\Entities\Attributes\Identifier;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

/** @ORM\Entity */
class Identity implements DoctrineAuthenticatorIdentity
{
	use Identifier;

	/** @ORM\Column(type="string", unique=true) */
	protected string $email;

	/** @ORM\Column(type="string") */
	protected string $password;

	/** @ORM\OneToMany(targetEntity="Session", mappedBy="identity") */
	protected Collection $sessions;

	protected string $token;

	public function __construct()
	{
		$this->sessions = new ArrayCollection();
	}

	public function getRoles(): array
	{
		return [];
	}

	public function getAuthToken(): string
	{
		return $this->token;
	}

	public function setAuthToken(string $token): self
	{
		$this->token = $token;
		return $this;
	}

	/**
	 * @return Session[]
	 */
	public function getSessions(): array
	{
		return $this->sessions->toArray();
	}

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
}
```

```php
<?php

namespace App\Model\Security;

use App\Model\Doctrine\EntityManager;
use App\Model\Entities\Identity;
use App\Model\Entities\Session;
use DateTimeImmutable;
use Nette\Http\Request;
use Nette\Security\Authorizator;
use Nette\Security\IAuthenticator;
use Nette\Security\IUserStorage;
use Nette\Security\User;
use Nette\Security\UserStorage;

/**
 * @method Identity getIdentity()
 * @property Authenticator $authenticator
 */
class SecurityUser extends User
{
	protected EntityManager $em;
	protected Request $httpRequest;

	public function __construct(EntityManager $em, Request $httpRequest, IUserStorage $legacyStorage = null, IAuthenticator $authenticator = null, Authorizator $authorizator = null, UserStorage $storage = null)
	{
		parent::__construct($legacyStorage, $authenticator, $authorizator, $storage);

		$this->em = $em;
		$this->httpRequest = $httpRequest;

		$this->onLoggedIn[] = function(SecurityUser $securityUser) {
			$identity = $securityUser->getIdentity();

			$session = new Session($identity, $identity->getAuthToken());
			$session
				->setValidUntil(new \DateTimeImmutable('+' . $this->authenticator->getExpiration()))
				->setIp($this->httpRequest->getRemoteAddress())
				->setUserAgent($this->httpRequest->getHeader('User-Agent'));
			$this->em->persist($session);
			$this->em->flush($session);
		};

		$this->onLoggedOut[] = function(SecurityUser $securityUser) {
			$identity = $securityUser->getIdentity();

			foreach ($identity->getSessions() as $_session) {
				if ($_session->getToken() === $identity->getAuthToken()) {
					$_session->setValidUntil(new DateTimeImmutable());
					$this->em->flush($_session);
					return;
				}
			}
		};
	}

	public function login($user, string $password = null): void
	{
		// ignore requests without User-Agent header, those are probably fakes
		if (empty($this->httpRequest->getHeader('User-Agent'))) {
			return;
		}

		parent::login($user, $password);
	}
}
```


```php
<?php

namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use App\Model\Entities\Identity;
use App\Model\Entities\Session;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Nette\Http\Request;
use Nette\Security\AuthenticationException;
use Nette\Security\IIdentity;
use Nette\Security\Passwords;
use Nette\Security\SimpleIdentity;
use Nette\Security\UserStorage;
use Nette\Utils\Random;

class Authenticator extends DoctrineAuthenticator
{
	public function __construct(
		protected readonly string $expiration,
		protected readonly EntityManagerInterface $em,
		protected readonly Request $httpRequest,
		UserStorage $userStorage
	) {
		parent::__construct($userStorage);

		$userStorage->setExpiration($expiration, false);
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

		$identity->setAuthToken(self::generateToken());

		return $identity;
	}

	/**
	 * @throws \Exception
	 */
	protected function getEntity(SimpleIdentity $identity): ?DoctrineAuthenticatorIdentity
	{
		/** @var Session $session */
		if (!$session = $this->em->getRepository(Session::class)
				->createQueryBuilder('e')
				->where('e.token = :token')
				->andWhere('e.validUntil >= :validUntil')
				->setParameters(['token' => $identity->getId(), 'validUntil' => new \DateTime()])
				->getQuery()
				->getOneOrNullResult()
		) {
			return null;
		}

		// Token was probably stolen
		if ($session->getUserAgent() !== $this->httpRequest->getHeader('User-Agent')) {
			$session->setValidUntil(new DateTimeImmutable());
			$this->em->flush($session);
			return null;
		}

		// Extend the expiration
		$session->setValidUntil(new DateTimeImmutable('+' . $this->expiration));

		// Create a new token to reduce the risk of theft
		$token = self::generateToken();
		$session->setRegeneratedAt(new DateTimeImmutable());
		$session->setToken($token);
		$identity->setId($token);

		$this->em->flush($session);

		return $session->getAuthEntity();
	}

	public function getExpiration(): string
	{
		return $this->expiration;
	}

	private static function generateToken(): string
	{
		return Random::generate(32);
	}
}
```
