<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

interface OnetimeTokenQueryFactory
{
	public function create(): OnetimeTokenQuery;
}