import { BaseProvider, ProviderOptions } from "@ezbackend/auth";
import { EzBackendInstance } from "@ezbackend/common";
import { FastifyInstance } from "fastify";
import { Strategy as LocalStrategy, IStrategyOptionsWithRequest } from 'passport-local'
import { RouteOptions } from 'fastify'
import fastifyPassport from 'fastify-passport'
import argon2 from 'argon2'

interface LocalProviderOptions extends ProviderOptions {
}

declare module "@ezbackend/auth" {
  interface EzBackendAuthOpts {
    local?: LocalProviderOptions
  }
}

export class LocalProvider extends BaseProvider {


  constructor(modelName: string) {
    super('local', modelName)
  }

  addStrategy(instance: EzBackendInstance, server: FastifyInstance, opts: LocalProviderOptions): [name: string, Strategy: any] {

    const that = this

    const localStrategy = new LocalStrategy(
      async function (username, password, done) {
        const idColumn = `${that.providerName}Id`
        const dataColumn = `${that.providerName}Data`
        const repo = instance.orm.getRepository(that.modelName)
        const user = await repo.findOne({
          where: {
            [idColumn]: username
          }
        })

        if (!user) {
          //New User
          const userProfile = {
            username: username,
            password: await argon2.hash(password)
          }
          that.defaultCallbackHandler(instance, username, userProfile, done)
        } else if (await argon2.verify(user[dataColumn].password, password)) {
          //Correct password
          that.defaultCallbackHandler(instance, username, user, done)
        } else {
          //Wrong Password
          done(new Error("Wrong username or password"))
        }

      }
    )

    return [this.providerName, localStrategy]
  }

  getLoginRoute(server: FastifyInstance, opts: any): RouteOptions {
    return {
      method: 'POST',
      url: `/${this.getRoutePrefixNoPrePostSlash(server)}/login`,
      preHandler: fastifyPassport.authenticate('local', { scope: opts.scope }),
      handler: async (req, res) => {
        return { loggedIn: true }
      },
      schema: {
        tags: ['Local Auth'],
        summary: `Login for model '${this.modelName}' with provider ${this.providerName}`,
        description: `POST your login data (username, password) to this url`,
        body: {
          type: 'object',
          properties: {
            username: { type: 'string' },
            password: { type: 'string' }
          }
        }
      },
    };
  }

  getLogoutRoute(server: FastifyInstance, opts: any): RouteOptions {
    return {
      method: 'GET',
      url: `/${this.getRoutePrefixNoPrePostSlash(server)}/logout`,
      handler: async (req, res) => {
        await req.logOut()
        return { loggedIn: false }
      },
      schema: {
        tags: ['Local Auth'],
        summary: `Logout for model '${this.modelName}' with provider ${this.providerName}`,
        description: `Getting this route will remove the session cookie`,
      },
    };
  }

  getCallbackRoute(server: FastifyInstance, opts: any): RouteOptions {
    const callbackRoute = `/${this.getRoutePrefixNoPrePostSlash(
      server,
    )}/callback`;
    return {
      method: 'GET',
      url: callbackRoute,
      preValidation: fastifyPassport.authenticate('local', {
        scope: opts.scope,
        successRedirect: opts.successRedirectURL,
        failureRedirect: opts.failureRedirectURL,
      }),
      handler: function (req, res) {
        res.redirect(opts.successRedirectURL);
      },
      schema: {
        tags: ['Local Auth'],
        summary: `Callback Route for model '${this.modelName}' with provider ${this.providerName}`,
        description: `This URL just redirects directly to the the successRedirectURL`,
      },
    };
  }

}