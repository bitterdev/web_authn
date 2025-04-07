<?php

namespace WebAuthn\Provider;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use Concrete\Core\Foundation\Service\Provider;
use Concrete\Core\Http\ResponseFactoryInterface;
use Concrete\Core\Routing\RouterInterface;
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
    protected RouterInterface $router;

    public function __construct(
        Application              $app,
        EventDispatcherInterface $eventDispatcher,
        Connection               $db,
        ResponseFactoryInterface $responseFactory,
        RouterInterface          $router
    )
    {
        parent::__construct($app);

        $this->eventDispatcher = $eventDispatcher;
        $this->db = $db;
        $this->responseFactory = $responseFactory;
        $this->router = $router;

        /** @noinspection PhpUnhandledExceptionInspection */
        $this->session = $this->app->make("session");
    }

    public function register()
    {
        $this->registerEventHandlers();
        $this->registerRoutes();
    }

    protected function registerRoutes()
    {
        // Make this routes public available
        $this->router->all('/login_public/web_authn/skip_register_passkey', '\Concrete\Package\WebAuthn\Authentication\WebAuthn\Controller::skip_register_passkey');
        $this->router->all('/login_public/web_authn/register_passkey', '\Concrete\Package\WebAuthn\Authentication\WebAuthn\Controller::register_passkey');
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