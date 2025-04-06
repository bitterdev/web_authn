<?php

namespace WebAuthn\Provider;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use Concrete\Core\Foundation\Service\Provider;
use Concrete\Core\Http\ResponseFactoryInterface;
use Concrete\Core\Support\Facade\Url;
use Concrete\Core\User\Event\User;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Session\Session;

class ServiceProvider extends Provider
{
    protected EventDispatcherInterface $eventDispatcher;
    protected Connection $db;
    protected ResponseFactoryInterface $responseFactory;
    protected Session $session;

    public function __construct(
        Application              $app,
        EventDispatcherInterface $eventDispatcher,
        Connection               $db,
        ResponseFactoryInterface $responseFactory
    )
    {
        parent::__construct($app);

        $this->eventDispatcher = $eventDispatcher;
        $this->db = $db;
        $this->responseFactory = $responseFactory;

        /** @noinspection PhpUnhandledExceptionInspection */
        $this->session = $this->app->make("session");
    }

    public function register()
    {
        $this->registerEventHandlers();
    }

    protected function registerEventHandlers()
    {
        $this->eventDispatcher->addListener("on_user_login", function ($event) {
            /** @var User $event */
            $user = $event->getUserObject();

            $uID = $user->getUserID();

            /** @noinspection SqlDialectInspection */
            /** @noinspection SqlNoDataSourceInspection */
            $countOfPasskeys = (int)$this->db->fetchOne("SELECT COUNT(*) FROM authTypeWebAuthn WHERE uID = ?", [
                $uID
            ]);

            if ($countOfPasskeys === 0) {
                $user->logout(false);

                $this->session->set("stored-user-id", $uID);
                $this->session->save();

                $this->responseFactory->redirect(Url::to('/login/web_authn', 'register_passkey'))->send();
                $this->app->shutdown();
            }
        });
    }
}