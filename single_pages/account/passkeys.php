<?php

defined('C5_EXECUTE') or die('Access Denied');

use Concrete\Core\Form\Service\Form;
use Concrete\Core\Page\Page;
use Concrete\Core\Support\Facade\Application;
use Concrete\Core\Support\Facade\Url;
use Concrete\Core\Validation\CSRF\Token;

/** @var stdClass $args */
/** @var array $passkeys */

$app = Application::getFacadeApplication();
/** @var Token $token */
/** @noinspection PhpUnhandledExceptionInspection */
$token = $app->make(Token::class);
/** @var Form $form */
/** @noinspection PhpUnhandledExceptionInspection */
$form = $app->make(Form::class);

?>

<h3>
    <?php echo t("Registered passkeys"); ?>
</h3>

<?php if (count($passkeys) === 0) { ?>
    <p>
        <?php echo t("No passkeys are available."); ?>
    </p>
<?php } else { ?>
    <table class="table table-striped">
        <thead>
        <tr>
            <th>
                <?php echo t("ID"); ?>
            </th>

            <th>
                &nbsp;
            </th>
        </tr>
        </thead>

        <tbody>
        <?php foreach ($passkeys as $passkey) { ?>
            <tr>
                <td>
                    <?php echo $passkey["id"]; ?>
                </td>

                <td>
                    <a href="<?php echo Url::to(Page::getCurrentPage(), "remove_passkey", $passkey["id"]) ?>">
                        <?php echo t("Remove Passkey"); ?>
                    </a>
                </td>
            </tr>
        <?php } ?>
        </tbody>
    </table>
<?php } ?>


<form method="post" action="<?php echo Url::to(Page::getCurrentPage(), 'register_passkey') ?>"
      id="passkey-register-form">
    <?php $token->output('register_passkey'); ?>

    <?php echo $form->hidden("clientDataJSON"); ?>
    <?php echo $form->hidden("attestationObject"); ?>

    <a href="javascript:void(0);" id="passkey-register">
        <?php echo t("Register Passkey"); ?>
    </a>
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

                $('#passkey-register')
                    .removeClass("disabled")
                    .on('click', function (e) {
                        e.preventDefault();
                        e.stopPropagation();

                        helper.bta(data);

                        navigator.credentials.create(data).then(credential => {
                            $("#clientDataJSON").val(credential.response.clientDataJSON ? helper.atb(credential.response.clientDataJSON) : null);
                            $("#attestationObject").val(credential.response.attestationObject ? helper.atb(credential.response.attestationObject) : null);

                            $("#passkey-register-form").submit();
                        });

                        return false;
                    });
            }
        });
    }
</script>