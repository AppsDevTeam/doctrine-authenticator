# Doctrine Authenticator

Allows you to use a Doctrine entity as a Nette identity.

## Example for CookieStorage

```neon
services:
	security.userStorage: ADT\DoctrineAuthenticator\CookieStorage
	security.authenticator: App\Model\Security\Authenticator('14 days', 'App\Model\Entity\SessionStorage', 'token')
```

```php
/**
 * @ORM\Entity
 */
class Session extends BaseEntity implements DoctrineAuthenticatorSession
{
	use Identifier;

	/** @ORM\ManyToOne(targetEntity="Profile", inversedBy="sessions") */
	protected Profile $profile;


	public function getToken(): string
	{
		return $this->token;
	}


	public function setToken(string $token): Session
	{
		$this->token = $token;
		return $this;
	}


	public function getProfile(): Profile
	{
		return $this->profile;
	}


	public function setProfile(Profile $profile): Session
	{
		$this->profile = $profile;
		return $this;
	}


	public function getAuthEntity(): IIdentity
	{
		return $this->profile;
	}
}
```

```php
/**
 * @ORM\Entity
 */
class User implements DoctrineAuthenticatorIdentity
{
	/** @ORM\OneToMany(targetEntity="Session", mappedBy="profile", cascade={"all"}) */
	protected $sessions;
	
	public function __construct()
	{
		$this->sessions = new ArrayCollection();
	}

	public function getAuthToken(): string
	{
		return $this->token;
	}
}
```

```php
namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use Nette\Security as NS;

class Authenticator extends DoctrineAuthenticator
{
	public function authenticate(string $user, string $password): NS\IIdentity
	{
		if (! $profile = $this->em->getRepository(Profile::class)->findBy(['email' => $user, 'password' => (new NS\Passwords)->hash($password)])) {
			throw new NS\AuthenticationException('User not found');
		}
		
		$session = new Session();
		$session->setToken(Random::generate(32));
		$session->setProfile($profile);
		$this->em->persist($session);
		$this->em->flush();
		
		return $profile;
	}
}
```


## Example for SessionStorage

```neon
services:
	security.userStorage: Nette\Bridges\SecurityHttp\SessionStorage
	security.authenticator: App\Model\Security\Authenticator('14 days', 'App\Model\Entity\User', 'id')
```

```php
/**
 * @ORM\Entity
 */
class User extends BaseEntity  implements IIdentity, UuidInterface, DoctrineAuthenticatorSession, DoctrineAuthenticatorIdentity
{
	public function getAuthEntity(): IIdentity
	{
		return $this;
	}

	public function getAuthToken(): string
	{
		return (string) $this->id;
	}
}
```

```php
namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use Nette\Security as NS;

class Authenticator extends DoctrineAuthenticator
{
	public function authenticate(string $user, string $password): NS\IIdentity
	{
		if (! $profile = $this->em->getRepository(Profile::class)->findBy(['email' => $user, 'password' => (new NS\Passwords)->hash($password)])) {
			throw new NS\AuthenticationException('User not found');
		}
		
		return $profile;
	}
}
```
