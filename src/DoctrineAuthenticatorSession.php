<?php

namespace ADT\DoctrineAuthenticator;

interface DoctrineAuthenticatorSession
{
	public function getAuthEntity(): DoctrineAuthenticatorIdentity;
}