import { NextFunction, Request, Response } from "express";
import { ParamsDictionary } from "express-serve-static-core";
import { ParsedQs } from "qs";
import { AuthenticationComponent } from "../../authentication/AuthenticationComponent";
import AppDataSource from "../../AppDataSource";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { config } from "../../../config";
import { CONSENT_ENTRYPOINT } from "../../authorization/constants";
import { openidForPresentationReceivingService, verifierConfigurationService } from "../../services/instances";
import { UserAuthenticationMethod } from "../../types/UserAuthenticationMethod.enum";
import { appContainer } from "../../services/inversify.config";
import { OpenidForPresentationsReceivingService } from "../../services/OpenidForPresentationReceivingService";
import locale from "../../configuration/locale";

export class GenericVIDAuthenticationComponent extends AuthenticationComponent {
	private openidForPresentationReceivingService = appContainer.resolve(OpenidForPresentationsReceivingService);

	constructor(
		override identifier: string,
		override protectedEndpoint: string,
		private mapping: { [authorizationServerStateColumnName: string] : { input_descriptor_constraint_field_name: string, parser?: (v: any) => string }},
		private presentationDefinitionId: string = "vid",
		private inputDescriptorId: string = "VID"
	) { super(identifier, protectedEndpoint) }

	public override async authenticate(
		req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
		res: Response<any, Record<string, any>>,
		next: NextFunction) {

		return super.authenticate(req, res, async () => {
			if (await this.dataHaveBeenExtracted(req)) {
				return next();
			}

			if (req.authorizationServerState.authenticationMethod &&
					req.authorizationServerState.authenticationMethod != UserAuthenticationMethod.VID_AUTH) {
				return next();
			}

			if (req.method == 'GET' && req.originalUrl.endsWith('/callback')) {
				console.log("rendering verifier/handle-response-code view...")
				return res.render('verifier/handle-response-code', {
					lang: req.lang,
					locale: locale[req.lang],
				})
			}

			if (req.method == 'POST' && req.originalUrl.endsWith('/callback')) {
				await this.handleCallback(req, res);
				return;
			}
			return this.askForPresentation(req, res);
		})
		.catch(() => {
			return next();
		});
	}

	private async dataHaveBeenExtracted(req: Request): Promise<boolean> {
		if (!req.cookies['session_id']) {
			return false;
		}
		const authorizationServerState = await AppDataSource.getRepository(AuthorizationServerState)
			.createQueryBuilder("authz_state")
			.where("authz_state.session_id = :session_id", { session_id: req.cookies['session_id'] })
			.getOne();

		if (!authorizationServerState) {
			return false;
		}

		const extractedValues = Object.keys(this.mapping).map((authorizationServerStateColumnName) => {
			// @ts-ignore
			return authorizationServerState[authorizationServerStateColumnName];		
		}).filter((x) => x != undefined && x != null);

		console.log("Extracted values = ", extractedValues);
		if (extractedValues.length == Object.keys(this.mapping).length) {
			return true
		}
		return false;
	}

	private async handleCallback(req: Request, res: Response): Promise<any> {
		if (!req.cookies['session_id']) {
			return false;
		}
		const result = await this.openidForPresentationReceivingService.getPresentationBySessionIdOrPresentationDuringIssuanceSession(req.cookies['session_id']);
		if (!result.status) {
			return false;
		}
		const vp_token = result.rpState.vp_token;

		console.log("Result = ", result)
		const authorizationServerState = await AppDataSource.getRepository(AuthorizationServerState)
			.createQueryBuilder("authz_state")
			.where("authz_state.session_id = :session_id", { session_id: result.rpState.session_id })
			.getOne();
		
		console.log("Authorization server state = ", authorizationServerState)

		if (!authorizationServerState || !vp_token || !result.rpState.claims || !result.rpState.claims["VID"]) {
			return false;
		}


		Object.keys(this.mapping).map((authorizationServerStateColumnName) => {
			const { input_descriptor_constraint_field_name, parser } = this.mapping[authorizationServerStateColumnName];
			console.log("Field name = ", input_descriptor_constraint_field_name)
			console.log("Field parser = ", parser)
			const fieldParser = parser ?? ((value: string) => value);

			// @ts-ignore
			authorizationServerState[authorizationServerStateColumnName] = fieldParser(result.rpState.claims[this.inputDescriptorId].filter((claim) => claim.name == input_descriptor_constraint_field_name)[0].value ?? null)
		});

		await AppDataSource.getRepository(AuthorizationServerState).save(authorizationServerState);
		res.redirect(this.protectedEndpoint);
		return true;
	}

	private async askForPresentation(req: Request, res: Response): Promise<any> {
		const presentationDefinition = JSON.parse(JSON.stringify(verifierConfigurationService.getPresentationDefinitions().filter(pd => pd.id == this.presentationDefinitionId)[0])) as any;

		try {
			const { url, stateId } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({req, res}, presentationDefinition, req.cookies['session_id'], config.url + CONSENT_ENTRYPOINT + '/callback');
			console.log("Authorization request url = ", url)
			// attach the vid_auth_state with an authorization server state
			req.authorizationServerState.vid_auth_state = stateId;
			await AppDataSource.getRepository(AuthorizationServerState).save(req.authorizationServerState);
			console.log("Authz state = ", req.authorizationServerState)
			return res.redirect(url.toString());

		}
		catch(err) {
			console.log(err);
			return res.redirect('/');
		}

	}
	
}
