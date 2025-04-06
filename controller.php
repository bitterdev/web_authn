<?php

namespace Concrete\Package\WebAuthn;

use Concrete\Core\Authentication\AuthenticationType;
use Concrete\Core\Package\Package;
use Concrete\Core\Entity\Package as PackageEntity;
use WebAuthn\Provider\ServiceProvider;

class Controller extends Package
{
    protected string $pkgHandle = 'web_authn';
    protected string $pkgVersion = '0.0.2';
    protected $appVersionRequired = '9.0.0';
    protected $pkgAutoloaderRegistries = [
        'src/WebAuthn' => 'WebAuthn',
    ];

    public function getPackageName(): string
    {
        return t('WebAuthn');
    }

    public function getPackageDescription(): string
    {
        return t('Authenticate users with Passkeys: fingerprints, patterns and biometric data.');
    }

    public function on_start()
    {
        require_once("vendor/autoload.php");

        /** @var ServiceProvider $serviceProvider */
        /** @noinspection PhpUnhandledExceptionInspection */
        $serviceProvider = $this->app->make(ServiceProvider::class);
        $serviceProvider->register();
    }

    public function install(): PackageEntity
    {
        $this->on_start();

        $pkg = parent::install();
        $this->installContentFile("data.xml");
        /** @noinspection PhpUnhandledExceptionInspection */
        $type = AuthenticationType::add('web_authn', 'Web Authn', 1, $pkg);
        $type->enable();
        return $pkg;
    }

    public function upgrade()
    {
        parent::upgrade();
        $this->installContentFile("data.xml");
    }
}


