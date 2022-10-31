# Doctrine Authenticator

Allows you to use a Doctrine entity as a Nette identity.

## Example for CookieStorage

```neon
services:
	security.userStorage: Nette\Bridges\SecurityHttp\CookieStorage
	security.authenticator: App\Model\Security\Authenticator('App\Model\Entity\SessionStorage', 'sessionId')
```

```php
/**
 * @ORM\Entity
 */
class Session extends BaseEntity implements DoctrineAuthenticatorSession
{
	use Identifier;

	/** @ORM\Column(type="string") */
	protected string $token;

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
	public function getAuthToken(): string
	{
		return $this->token;
	}
}
```


## Example for SessionStorage

```neon
services:
	security.userStorage: Nette\Bridges\SecurityHttp\SessionStorage
	security.authenticator: App\Model\Security\Authenticator('App\Model\Entity\User', 'id')
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

## Example of Authenticator

```php
namespace App\Model\Security;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use Nette\Security as NS;

class Authenticator extends DoctrineAuthenticator
{
	public function authenticate(string $user, string $password): NS\IIdentity
	{
		// your authentication belongs here
	}
}
```
