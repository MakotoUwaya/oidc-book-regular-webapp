const oidcProvider = 'es-dev-camp-dev.auth0.com';
const clientId = 'ukLtC7IqjzoKSac0fNE0CqvT3EV6LUB9';
const audience = 'https://to-dos.spmedomain.com';

// constants that represent configuration you won‘t need to change
const redirectURI = 'http://localhost:3002/#callback';
const scope = 'read:to-dos';

// user data
let accessToken = '';
let profile = '';

async function init() {
  return await createAuth0Client({
    domain: oidcProvider,
    client_id: clientId,
    redirect_uri: redirectURI,
    audience: audience,
    scope: scope
  });
}

async function login() {
  const auth0 = await init();
  await auth0.loginWithRedirect();
}

async function handleRedirectCallback() {
  const auth0 = await init();
  await auth0.handleRedirectCallback();
  profile = await auth0.getUser();
  accessToken = await auth0.getTokenSilently();
}

function isAuthenticated() {
  return profile;
}

function getProfile() {
  return profile;
}

function getAccessToken() {
  return accessToken;
}