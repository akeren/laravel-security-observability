<?php

declare(strict_types=1);

namespace Kater\SecurityObservability\Security;

/** Observations supplied by the host; these never enforce policy or infer detections. */
enum SecurityAction: string
{
    case AuthorizationDenied = 'access.authorization.denied';
    case MfaEnrolled = 'identity.mfa.enrolled';
    case MfaRemoved = 'identity.mfa.removed';
    case MfaFailed = 'identity.mfa.failed';
    case CredentialRotated = 'identity.credential.rotated';
    case CredentialRevoked = 'identity.credential.revoked';
    case PrivilegeChanged = 'identity.privilege.changed';
    case ImpersonationStarted = 'identity.impersonation.started';
    case ImpersonationEnded = 'identity.impersonation.ended';
    case SensitiveExport = 'data.sensitive.exported';

    public function action(): string
    {
        return match ($this) {
            self::AuthorizationDenied => 'deny', self::MfaEnrolled => 'enroll',
            self::MfaRemoved => 'remove', self::MfaFailed => 'verify',
            self::CredentialRotated => 'rotate', self::CredentialRevoked => 'revoke',
            self::PrivilegeChanged => 'change', self::ImpersonationStarted => 'start',
            self::ImpersonationEnded => 'end', self::SensitiveExport => 'export',
        };
    }
}
