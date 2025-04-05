<?php

defined('C5_EXECUTE') or die('Access Denied');

use Concrete\Core\Authentication\AuthenticationType;
use Concrete\Core\Form\Service\Form;
use Concrete\Core\Support\Facade\Application;
use Concrete\Core\Support\Facade\Url;
use Concrete\Core\Validation\CSRF\Token;

/** @var stdClass $args */
/** @var AuthenticationType $this */

$app = Application::getFacadeApplication();
/** @var Token $token */
/** @noinspection PhpUnhandledExceptionInspection */
$token = $app->make(Token::class);
/** @var Form $form */
/** @noinspection PhpUnhandledExceptionInspection */
$form = $app->make(Form::class);
?>

<div class="text-center">
    <form method="post" action="<?php echo Url::to('/login', 'authenticate', $this->getAuthenticationTypeHandle()) ?>"
          id="passkey-login-form">
        <?php $token->output('login_' . $this->getAuthenticationTypeHandle()); ?>

        <?php echo $form->hidden("credentialId"); ?>
        <?php echo $form->hidden("clientDataJSON"); ?>
        <?php echo $form->hidden("authenticatorData"); ?>
        <?php echo $form->hidden("signature"); ?>
        <?php echo $form->hidden("userHandle"); ?>

        <button class="btn btn-primary disabled" id="passkey-login">
            <?php echo t("Login with Passkey"); ?>
        </button>
    </form>

    <!--suppress JSUnresolvedVariable, JSCheckFunctionSignatures -->
    <script>
        const data = <?php echo json_encode($args); ?>;

        let helper = {
            atb: b => {
                let u = new Uint8Array(b), s = "";
                for (let i = 0; i < u.byteLength; i++) {
                    s += String.fromCharCode(u[i]);
                }
                return btoa(s);
            },
            bta: o => {
                let pre = "=?BINARY?B?", suf = "?=";
                for (let k in o) {
                    if (typeof o[k] == "string") {
                        let s = o[k];
                        if (s.substring(0, pre.length) === pre && s.substring(s.length - suf.length) === suf) {
                            let b = window.atob(s.substring(pre.length, s.length - suf.length)),
                                u = new Uint8Array(b.length);
                            for (let i = 0; i < b.length; i++) {
                                u[i] = b.charCodeAt(i);
                            }
                            o[k] = u.buffer;
                        }
                    } else {
                        helper.bta(o[k]);
                    }
                }
            }
        };

        if (window.PublicKeyCredential &&
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
            PublicKeyCredential.isConditionalMediationAvailable) {

            Promise.all([
                PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
                PublicKeyCredential.isConditionalMediationAvailable(),
            ]).then(results => {
                if (results.every(r => r === true)) {
                    helper.bta(data);

                    $('#passkey-login')
                        .removeClass("disabled")
                        .on('click', function (e) {
                            e.preventDefault();
                            e.stopPropagation();

                            navigator.credentials.get(data).then(credential => {
                                $("#credentialId").val(credential.rawId ? helper.atb(credential.rawId) : null);
                                $("#clientDataJSON").val(credential.response.clientDataJSON ? helper.atb(credential.response.clientDataJSON) : null);
                                $("#authenticatorData").val(credential.response.authenticatorData ? helper.atb(credential.response.authenticatorData) : null);
                                $("#signature").val(credential.response.signature ? helper.atb(credential.response.signature) : null);
                                $("#userHandle").val(credential.response.userHandle ? helper.atb(credential.response.userHandle) : null);

                                $("#passkey-login-form").submit();
                            });

                            return false;
                        });
                }
            });
        }
    </script>
</div>