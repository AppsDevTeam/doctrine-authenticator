<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use Doctrine\ORM\QueryBuilder;

trait OnetimeTokenQueryTrait
{
	public function byToken(string $hashedToken, ?string $identifier = null): static
	{
		$this->filter[] = function (QueryBuilder $qb) use ($hashedToken, $identifier) {
			$qb->andWhere('e.token = :token')
				->setParameter('token', $hashedToken);

			if ($identifier) {
				$qb->andWhere('(e.identifier = :identifier OR e.identifier IS NULL)')
					->setParameter('identifier', $identifier);
			} else {
				$qb->andWhere('e.identifier IS NULL');
			}
		};
		
		return $this;
	}

	public function byType(string $type): static
	{
		return $this->by('type', $type);
	}

	public function byIsValid(bool $checkValidUntil = true): static
	{
		if ($checkValidUntil) {
			$this->filter[] = function (QueryBuilder $qb) {
				$qb->andWhere('e.validUntil >= :now')
					->andWhere('e.usedAt IS NULL')
					->setParameter('now', new \DateTimeImmutable());
			};
			return $this;
		}

		return $this->by('usedAt', null);
	}
}