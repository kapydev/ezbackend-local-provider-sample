import { EzBackend } from '@ezbackend/common';
import { EzOpenAPI } from '@ezbackend/openapi';
import { EzDbUI } from '@ezbackend/db-ui';
import { EzCors } from '@ezbackend/cors';
import { EzAuth, EzUser } from "@ezbackend/auth"

import { LocalProvider } from './auth-providers/local.provider';

const app = new EzBackend();

// ---Plugins---
// Everything is an ezapp in ezbackend
app.addApp(new EzOpenAPI());
app.addApp(new EzDbUI());
app.addApp(new EzCors());
app.addApp(new EzAuth());
// ---Plugins---

// Models are also ezapps in ezbackend
const user = new EzUser('User', [LocalProvider]);

user.get('/my-data', async (req, res) => {
  //Specifically leave out the password hash
  return {
    id: req.user.id,
    localId: req.user.localId,
    localData: {
      username: req.user.localData.username
    }
  }
})

app.addApp(user, { prefix: 'user' });

app.start();
