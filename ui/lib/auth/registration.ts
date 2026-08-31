import { getBackendBaseUrl } from "@/lib/graphql/client";

export type PublicAuthConfig = {
  signup_enabled?: boolean;
  self_registration_enabled?: boolean;
  oauth_providers: string[];
  email_verification_required: boolean;
  dev_allow_unverified_email_login: boolean;
};

export type RegistrationAvailability = {
  uiRegistrationEnabled: boolean;
  selfRegistrationEnabled: boolean;
  enabled: boolean;
  configLoaded: boolean;
  emailVerificationRequired: boolean;
  devAllowUnverifiedEmailLogin: boolean;
};

export function isUiRegistrationEnabled() {
  return envBoolDefault("ATOM_UI_REGISTRATION_ENABLED", true);
}

export async function getRegistrationAvailability(): Promise<RegistrationAvailability> {
  const uiRegistrationEnabled = isUiRegistrationEnabled();
  if (!uiRegistrationEnabled) {
    return disabledAvailability({ uiRegistrationEnabled, configLoaded: false });
  }

  try {
    const config = await getPublicAuthConfig();
    const selfRegistrationEnabled =
      config.self_registration_enabled ?? config.signup_enabled ?? false;

    return {
      uiRegistrationEnabled,
      selfRegistrationEnabled,
      enabled: uiRegistrationEnabled && selfRegistrationEnabled,
      configLoaded: true,
      emailVerificationRequired: config.email_verification_required,
      devAllowUnverifiedEmailLogin: config.dev_allow_unverified_email_login,
    };
  } catch {
    return disabledAvailability({ uiRegistrationEnabled, configLoaded: false });
  }
}

async function getPublicAuthConfig(): Promise<PublicAuthConfig> {
  const response = await fetch(`${getBackendBaseUrl()}/auth/public-config`, {
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error("Unable to load auth configuration");
  }
  return response.json() as Promise<PublicAuthConfig>;
}

function disabledAvailability({
  uiRegistrationEnabled,
  configLoaded,
}: {
  uiRegistrationEnabled: boolean;
  configLoaded: boolean;
}): RegistrationAvailability {
  return {
    uiRegistrationEnabled,
    selfRegistrationEnabled: false,
    enabled: false,
    configLoaded,
    emailVerificationRequired: true,
    devAllowUnverifiedEmailLogin: false,
  };
}

function envBoolDefault(name: string, defaultValue: boolean) {
  const value = process.env[name]?.trim().toLowerCase();
  if (!value) return defaultValue;
  return ["1", "true", "yes", "on"].includes(value);
}
