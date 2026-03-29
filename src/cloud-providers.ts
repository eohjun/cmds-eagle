import { promises as fs } from 'fs';
import { requestUrl, Notice, Platform } from 'obsidian';
import { shell } from 'electron';
import * as http from 'http';
import * as url from 'url';
import {
	CloudUploadResult,
	R2ProviderConfig,
	S3ProviderConfig,
	WebDAVProviderConfig,
	ImgHippoProviderConfig,
	CustomProviderConfig,
	GoogleDriveProviderConfig,
	AnyCloudProviderConfig,
} from './types';

export interface CloudProvider {
	upload(filePath: string, filename: string, mimeType: string): Promise<CloudUploadResult>;
	testConnection(): Promise<boolean>;
	getPublicUrl(key: string): string;
}

function getMimeType(ext: string): string {
	const MIME_TYPES: Record<string, string> = {
		'jpg': 'image/jpeg',
		'jpeg': 'image/jpeg',
		'png': 'image/png',
		'gif': 'image/gif',
		'webp': 'image/webp',
		'svg': 'image/svg+xml',
		'bmp': 'image/bmp',
		'ico': 'image/x-icon',
		'tiff': 'image/tiff',
		'tif': 'image/tiff',
		'heic': 'image/heic',
		'heif': 'image/heif',
		'avif': 'image/avif',
		'pdf': 'application/pdf',
	};
	return MIME_TYPES[ext.toLowerCase()] || 'application/octet-stream';
}

export class R2Provider implements CloudProvider {
	constructor(private config: R2ProviderConfig) {}

	async upload(filePath: string, filename: string, mimeType: string): Promise<CloudUploadResult> {
		if (!this.config.workerUrl || !this.config.apiKey) {
			return { success: false, error: 'R2 not configured' };
		}

		try {
			const fileBuffer = await fs.readFile(filePath);
			const blob = new Blob([fileBuffer], { type: mimeType });

			const formData = new FormData();
			formData.append('file', blob, filename);
			formData.append('filename', filename);
			formData.append('content_type', mimeType);

			const response = await fetch(`${this.config.workerUrl}/upload`, {
				method: 'POST',
				headers: {
					'Authorization': `Bearer ${this.config.apiKey}`,
				},
				body: formData,
			});

			if (!response.ok) {
				const errorText = await response.text();
				return { success: false, error: `Upload failed (${response.status}): ${errorText}` };
			}

			const result = await response.json() as { success: boolean; key: string; filename: string };
			return {
				success: true,
				key: result.key,
				filename: result.filename,
				publicUrl: this.getPublicUrl(result.key),
			};
		} catch (error) {
			return { 
				success: false, 
				error: error instanceof Error ? error.message : 'Unknown error' 
			};
		}
	}

	async testConnection(): Promise<boolean> {
		if (!this.config.workerUrl || !this.config.apiKey) {
			return false;
		}
		try {
			const response = await fetch(`${this.config.workerUrl}/health`, {
				method: 'GET',
				headers: {
					'Authorization': `Bearer ${this.config.apiKey}`,
				},
			});
			return response.status === 200;
		} catch {
			return false;
		}
	}

	getPublicUrl(key: string): string {
		return `${this.config.publicUrl}/${key}`;
	}
}

export class S3Provider implements CloudProvider {
	constructor(private config: S3ProviderConfig) {}

	async upload(filePath: string, filename: string, mimeType: string): Promise<CloudUploadResult> {
		if (!this.config.endpoint || !this.config.accessKeyId || !this.config.secretAccessKey) {
			return { success: false, error: 'S3 not configured' };
		}

		try {
			const fileBuffer = await fs.readFile(filePath);
			const key = `eagle/${Date.now()}-${filename}`;
			
			const date = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
			const dateStamp = date.slice(0, 8);
			
			const host = new URL(this.config.endpoint).host;
			const canonicalUri = `/${this.config.bucket}/${key}`;
			const canonicalQueryString = '';
			const payloadHash = await this.sha256(fileBuffer);
			
			const canonicalHeaders = [
				`content-type:${mimeType}`,
				`host:${host}`,
				`x-amz-content-sha256:${payloadHash}`,
				`x-amz-date:${date}`,
			].join('\n') + '\n';
			
			const signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';
			
			const canonicalRequest = [
				'PUT',
				canonicalUri,
				canonicalQueryString,
				canonicalHeaders,
				signedHeaders,
				payloadHash,
			].join('\n');
			
			const algorithm = 'AWS4-HMAC-SHA256';
			const credentialScope = `${dateStamp}/${this.config.region}/s3/aws4_request`;
			const stringToSign = [
				algorithm,
				date,
				credentialScope,
				await this.sha256(new TextEncoder().encode(canonicalRequest)),
			].join('\n');
			
			const signingKey = await this.getSignatureKey(
				this.config.secretAccessKey,
				dateStamp,
				this.config.region,
				's3'
			);
			const signature = await this.hmacHex(signingKey, stringToSign);
			
			const authorizationHeader = `${algorithm} Credential=${this.config.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
			
			const response = await fetch(`${this.config.endpoint}/${this.config.bucket}/${key}`, {
				method: 'PUT',
				headers: {
					'Content-Type': mimeType,
					'x-amz-content-sha256': payloadHash,
					'x-amz-date': date,
					'Authorization': authorizationHeader,
				},
				body: fileBuffer,
			});

			if (!response.ok) {
				const errorText = await response.text();
				return { success: false, error: `S3 upload failed (${response.status}): ${errorText}` };
			}

			return {
				success: true,
				key: key,
				filename: filename,
				publicUrl: this.getPublicUrl(key),
			};
		} catch (error) {
			return { 
				success: false, 
				error: error instanceof Error ? error.message : 'Unknown error' 
			};
		}
	}

	async testConnection(): Promise<boolean> {
		if (!this.config.endpoint || !this.config.accessKeyId) {
			return false;
		}
		try {
			const response = await fetch(`${this.config.endpoint}/${this.config.bucket}`, {
				method: 'HEAD',
			});
			return response.status < 500;
		} catch {
			return false;
		}
	}

	getPublicUrl(key: string): string {
		if (this.config.publicUrl) {
			return `${this.config.publicUrl}/${key}`;
		}
		return `${this.config.endpoint}/${this.config.bucket}/${key}`;
	}

	private async sha256(data: ArrayBuffer | Uint8Array): Promise<string> {
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);
		return Array.from(new Uint8Array(hashBuffer))
			.map(b => b.toString(16).padStart(2, '0'))
			.join('');
	}

	private async hmac(key: ArrayBuffer, data: string): Promise<ArrayBuffer> {
		const cryptoKey = await crypto.subtle.importKey(
			'raw',
			key,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign']
		);
		return await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
	}

	private async hmacHex(key: ArrayBuffer, data: string): Promise<string> {
		const sig = await this.hmac(key, data);
		return Array.from(new Uint8Array(sig))
			.map(b => b.toString(16).padStart(2, '0'))
			.join('');
	}

	private async getSignatureKey(
		key: string,
		dateStamp: string,
		region: string,
		service: string
	): Promise<ArrayBuffer> {
		const kDate = await this.hmac(new TextEncoder().encode('AWS4' + key), dateStamp);
		const kRegion = await this.hmac(kDate, region);
		const kService = await this.hmac(kRegion, service);
		return await this.hmac(kService, 'aws4_request');
	}
}

export class WebDAVProvider implements CloudProvider {
	constructor(private config: WebDAVProviderConfig) {}

	async upload(filePath: string, filename: string, mimeType: string): Promise<CloudUploadResult> {
		if (!this.config.serverUrl || !this.config.username) {
			return { success: false, error: 'WebDAV not configured' };
		}

		try {
			const fileBuffer = await fs.readFile(filePath);
			const key = `${this.config.uploadPath}/${Date.now()}-${filename}`;
			const uploadUrl = `${this.config.serverUrl}${key}`;

			const auth = btoa(`${this.config.username}:${this.config.password}`);

			const response = await fetch(uploadUrl, {
				method: 'PUT',
				headers: {
					'Authorization': `Basic ${auth}`,
					'Content-Type': mimeType,
				},
				body: fileBuffer,
			});

			if (!response.ok && response.status !== 201 && response.status !== 204) {
				return { success: false, error: `WebDAV upload failed (${response.status})` };
			}

			return {
				success: true,
				key: key,
				filename: filename,
				publicUrl: this.getPublicUrl(key),
			};
		} catch (error) {
			return { 
				success: false, 
				error: error instanceof Error ? error.message : 'Unknown error' 
			};
		}
	}

	async testConnection(): Promise<boolean> {
		if (!this.config.serverUrl || !this.config.username) {
			return false;
		}
		try {
			const auth = btoa(`${this.config.username}:${this.config.password}`);
			const response = await fetch(this.config.serverUrl, {
				method: 'PROPFIND',
				headers: {
					'Authorization': `Basic ${auth}`,
					'Depth': '0',
				},
			});
			return response.status === 207 || response.status === 200;
		} catch {
			return false;
		}
	}

	getPublicUrl(key: string): string {
		if (this.config.publicUrl) {
			return `${this.config.publicUrl}${key}`;
		}
		return `${this.config.serverUrl}${key}`;
	}
}

export class ImgHippoProvider implements CloudProvider {
	private readonly API_URL = 'https://api.imghippo.com/v1/upload';
	
	constructor(private config: ImgHippoProviderConfig) {}

	async upload(filePath: string, filename: string, mimeType: string): Promise<CloudUploadResult> {
		if (!this.config.apiKey) {
			return { success: false, error: 'ImgHippo API key not configured' };
		}

		try {
			const fileBuffer = await fs.readFile(filePath);
			const blob = new Blob([fileBuffer], { type: mimeType });

			const formData = new FormData();
			formData.append('api_key', this.config.apiKey);
			formData.append('file', blob, filename);
			formData.append('title', filename);

			const response = await fetch(this.API_URL, {
				method: 'POST',
				body: formData,
			});

			if (!response.ok) {
				const errorText = await response.text();
				return { success: false, error: `ImgHippo upload failed (${response.status}): ${errorText}` };
			}

			const result = await response.json() as {
				success: boolean;
				status: number;
				message?: string;
				data?: {
					id: string;
					title: string;
					url_viewer: string;
					url: string;
					display_url: string;
					width: string;
					height: string;
					size: string;
					time: string;
					expiration: string;
					image: {
						filename: string;
						name: string;
						mime: string;
						extension: string;
						url: string;
					};
					thumb: {
						filename: string;
						name: string;
						mime: string;
						extension: string;
						url: string;
					};
					delete_url: string;
				};
			};

			if (!result.success || !result.data) {
				return { success: false, error: result.message || 'Upload failed' };
			}

			const publicUrl = result.data.url || result.data.display_url || result.data.image?.url;
			const resultFilename = result.data.image?.filename || result.data.title || filename;

			if (!publicUrl) {
				return { success: false, error: 'No URL returned from ImgHippo' };
			}

			return {
				success: true,
				key: result.data.id,
				filename: resultFilename,
				publicUrl: publicUrl,
			};
		} catch (error) {
			return { 
				success: false, 
				error: error instanceof Error ? error.message : 'Unknown error' 
			};
		}
	}

	async testConnection(): Promise<boolean> {
		return !!this.config.apiKey;
	}

	getPublicUrl(key: string): string {
		return key;
	}
}

export class CustomProvider implements CloudProvider {
	constructor(private config: CustomProviderConfig) {}

	async upload(filePath: string, filename: string, mimeType: string): Promise<CloudUploadResult> {
		if (!this.config.uploadUrl) {
			return { success: false, error: 'Custom provider not configured' };
		}

		try {
			const fileBuffer = await fs.readFile(filePath);
			const blob = new Blob([fileBuffer], { type: mimeType });

			const formData = new FormData();
			formData.append('file', blob, filename);
			formData.append('filename', filename);

			const response = await fetch(this.config.uploadUrl, {
				method: 'POST',
				headers: this.config.headers,
				body: formData,
			});

			if (!response.ok) {
				const errorText = await response.text();
				return { success: false, error: `Upload failed (${response.status}): ${errorText}` };
			}

			const result = await response.json() as { key?: string; url?: string; filename?: string };
			const key = result.key || result.url || filename;
			
			return {
				success: true,
				key: key,
				filename: result.filename || filename,
				publicUrl: this.getPublicUrl(key),
			};
		} catch (error) {
			return { 
				success: false, 
				error: error instanceof Error ? error.message : 'Unknown error' 
			};
		}
	}

	async testConnection(): Promise<boolean> {
		if (!this.config.uploadUrl) {
			return false;
		}
		try {
			const response = await fetch(this.config.uploadUrl, {
				method: 'HEAD',
				headers: this.config.headers,
			});
			return response.status < 500;
		} catch {
			return false;
		}
	}

	getPublicUrl(key: string): string {
		if (this.config.publicUrl) {
			return key.startsWith('http') ? key : `${this.config.publicUrl}/${key}`;
		}
		return key;
	}
}

export class GoogleDriveProvider implements CloudProvider {
	private static readonly AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
	private static readonly TOKEN_URL = 'https://oauth2.googleapis.com/token';
	private static readonly API_URL = 'https://www.googleapis.com/drive/v3';
	private static readonly UPLOAD_URL = 'https://www.googleapis.com/upload/drive/v3';
	private static readonly SCOPES = [
		'https://www.googleapis.com/auth/drive.file',
		'https://www.googleapis.com/auth/userinfo.email'
	];

	private server: http.Server | null = null;
	private timeoutId: ReturnType<typeof setTimeout> | null = null;
	private folderIdCache = new Map<string, string>();

	constructor(
		private config: GoogleDriveProviderConfig,
		private onConfigUpdate?: (config: GoogleDriveProviderConfig) => Promise<void>
	) {}

	async upload(filePath: string, filename: string, mimeType: string): Promise<CloudUploadResult> {
		if (!this.config.accessToken || !this.config.refreshToken) {
			return { success: false, error: 'Google Drive not authorized. Please connect in settings.' };
		}

		try {
			const fileBuffer = await fs.readFile(filePath);
			const base64Data = Buffer.from(fileBuffer).toString('base64');

			const accessToken = await this.ensureValidToken();
			const folderId = await this.ensureFolder(this.config.driveFolder);

			const metadata = {
				name: filename,
				mimeType: mimeType,
				parents: [folderId]
			};

			const boundary = '-------314159265358979323846';
			const delimiter = `\r\n--${boundary}\r\n`;
			const closeDelimiter = `\r\n--${boundary}--`;

			const multipartBody =
				delimiter +
				'Content-Type: application/json\r\n\r\n' +
				JSON.stringify(metadata) +
				delimiter +
				`Content-Type: ${mimeType}\r\n` +
				'Content-Transfer-Encoding: base64\r\n\r\n' +
				base64Data +
				closeDelimiter;

			const uploadResponse = await requestUrl({
				url: `${GoogleDriveProvider.UPLOAD_URL}/files?uploadType=multipart&fields=id,name,mimeType`,
				method: 'POST',
				headers: {
					'Authorization': `Bearer ${accessToken}`,
					'Content-Type': `multipart/related; boundary=${boundary}`
				},
				body: multipartBody
			});

			if (uploadResponse.status !== 200) {
				return { success: false, error: `Drive upload failed: ${uploadResponse.status}` };
			}

			const fileData = uploadResponse.json;
			if (!fileData?.id) {
				return { success: false, error: 'Upload response missing file ID' };
			}

			const fileId = fileData.id as string;

			await this.makeFilePublic(fileId, accessToken);
			const fileInfo = await this.getFileInfo(fileId, accessToken);

			const publicUrl = fileInfo.webContentLink
				|| `https://drive.google.com/uc?export=view&id=${fileId}`;

			return {
				success: true,
				key: fileId,
				filename: filename,
				publicUrl: publicUrl,
			};
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Unknown error'
			};
		}
	}

	async testConnection(): Promise<boolean> {
		if (!this.config.accessToken) return false;
		try {
			const accessToken = await this.ensureValidToken();
			const response = await requestUrl({
				url: `${GoogleDriveProvider.API_URL}/about?fields=user`,
				method: 'GET',
				headers: { 'Authorization': `Bearer ${accessToken}` }
			});
			return response.status === 200;
		} catch {
			return false;
		}
	}

	async testConnectionWithEmail(): Promise<{ connected: boolean; email?: string }> {
		if (!this.config.accessToken) return { connected: false };
		try {
			const accessToken = await this.ensureValidToken();
			const response = await requestUrl({
				url: `${GoogleDriveProvider.API_URL}/about?fields=user`,
				method: 'GET',
				headers: { 'Authorization': `Bearer ${accessToken}` }
			});
			if (response.status === 200) {
				return { connected: true, email: response.json?.user?.emailAddress };
			}
			return { connected: false };
		} catch {
			return { connected: false };
		}
	}

	getPublicUrl(key: string): string {
		return `https://drive.google.com/uc?export=view&id=${key}`;
	}

	isConnected(): boolean {
		return !!(this.config.accessToken && this.config.refreshToken);
	}

	disconnect(): void {
		this.config.accessToken = '';
		this.config.refreshToken = '';
		this.config.tokenExpiresAt = 0;
		this.folderIdCache.clear();
	}

	async authorize(): Promise<{ accessToken: string; refreshToken: string; expiresAt: number }> {
		if (!Platform.isDesktop) {
			throw new Error('Google Drive authorization requires the desktop app.');
		}
		if (!this.config.clientId || !this.config.clientSecret) {
			throw new Error('Please enter Client ID and Client Secret first.');
		}

		const codeVerifier = this.generateCodeVerifier();
		const codeChallenge = await this.generateCodeChallenge(codeVerifier);
		const redirectUri = `http://localhost:${this.config.redirectPort}/callback`;

		return new Promise((resolve, reject) => {
			try {
				this.server = http.createServer(async (req, res) => {
					try {
						const parsedUrl = url.parse(req.url || '', true);
						if (parsedUrl.pathname !== '/callback') return;

						const code = parsedUrl.query.code as string;
						const oauthError = parsedUrl.query.error as string;

						if (oauthError) {
							res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
							res.end(this.getResultHtml(false, oauthError));
							this.cleanupServer();
							reject(new Error(`OAuth error: ${oauthError}`));
							return;
						}

						if (code) {
							try {
								const tokens = await this.exchangeCodeForTokens(code, codeVerifier, redirectUri);
								res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
								res.end(this.getResultHtml(true));
								this.cleanupServer();
								resolve(tokens);
							} catch (tokenError) {
								const msg = tokenError instanceof Error ? tokenError.message : String(tokenError);
								res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
								res.end(this.getResultHtml(false, msg));
								this.cleanupServer();
								reject(new Error(`Token exchange failed: ${msg}`));
							}
						}
					} catch (err) {
						reject(err instanceof Error ? err : new Error(String(err)));
					}
				});

				this.server.listen(this.config.redirectPort);

				this.server.on('error', (err: NodeJS.ErrnoException) => {
					if (err.code === 'EADDRINUSE') {
						reject(new Error(`Port ${this.config.redirectPort} is in use. Change the OAuth port in settings.`));
					} else {
						reject(err);
					}
				});

				const params = new URLSearchParams({
					client_id: this.config.clientId,
					redirect_uri: redirectUri,
					response_type: 'code',
					scope: GoogleDriveProvider.SCOPES.join(' '),
					access_type: 'offline',
					prompt: 'consent',
					code_challenge: codeChallenge,
					code_challenge_method: 'S256'
				});
				const authUrl = `${GoogleDriveProvider.AUTH_URL}?${params.toString()}`;

				new Notice('Please log in with Google in your browser...', 3000);
				void shell.openExternal(authUrl);

				this.timeoutId = setTimeout(() => {
					this.cleanupServer();
					reject(new Error('OAuth flow timed out (2 min). Please try again.'));
				}, 120000);
			} catch (error) {
				this.cleanupServer();
				reject(error instanceof Error ? error : new Error(String(error)));
			}
		});
	}

	// ── Token management ────────────────────────────────

	private async ensureValidToken(): Promise<string> {
		if (this.config.tokenExpiresAt && this.config.refreshToken) {
			const bufferTime = 5 * 60 * 1000;
			if (Date.now() >= (this.config.tokenExpiresAt - bufferTime)) {
				const newTokens = await this.refreshAccessToken(this.config.refreshToken);
				this.config.accessToken = newTokens.accessToken;
				this.config.tokenExpiresAt = newTokens.expiresAt;
				if (this.onConfigUpdate) {
					await this.onConfigUpdate(this.config);
				}
			}
		}

		if (!this.config.accessToken) {
			throw new Error('Not connected to Google Drive. Please connect in settings.');
		}

		return this.config.accessToken;
	}

	private async refreshAccessToken(refreshToken: string): Promise<{ accessToken: string; expiresAt: number }> {
		const response = await requestUrl({
			url: GoogleDriveProvider.TOKEN_URL,
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				client_id: this.config.clientId,
				client_secret: this.config.clientSecret,
				refresh_token: refreshToken,
				grant_type: 'refresh_token'
			}).toString()
		});

		if (response.status !== 200) {
			throw new Error(`Token refresh failed (${response.status})`);
		}

		const data = response.json;
		return {
			accessToken: data.access_token,
			expiresAt: Date.now() + (data.expires_in * 1000),
		};
	}

	private async exchangeCodeForTokens(
		code: string, codeVerifier: string, redirectUri: string
	): Promise<{ accessToken: string; refreshToken: string; expiresAt: number }> {
		const response = await requestUrl({
			url: GoogleDriveProvider.TOKEN_URL,
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				code,
				client_id: this.config.clientId,
				client_secret: this.config.clientSecret,
				redirect_uri: redirectUri,
				grant_type: 'authorization_code',
				code_verifier: codeVerifier
			}).toString(),
			throw: false
		});

		if (response.status !== 200) {
			const errorDesc = response.json?.error_description || response.json?.error || `status ${response.status}`;
			throw new Error(`Token exchange failed: ${errorDesc}`);
		}

		const data = response.json;
		return {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			expiresAt: Date.now() + (data.expires_in * 1000),
		};
	}

	// ── Drive folder management ─────────────────────────

	private async ensureFolder(folderPath: string): Promise<string> {
		const parts = folderPath.split('/').filter(p => p.length > 0);
		let parentId = 'root';
		let cumulativePath = '';

		for (const folderName of parts) {
			cumulativePath += '/' + folderName;

			const cached = this.folderIdCache.get(cumulativePath);
			if (cached) {
				parentId = cached;
				continue;
			}

			const existingId = await this.findFolder(folderName, parentId);
			if (existingId) {
				parentId = existingId;
			} else {
				parentId = await this.createFolder(folderName, parentId);
			}

			this.folderIdCache.set(cumulativePath, parentId);
		}

		return parentId;
	}

	private async findFolder(name: string, parentId: string): Promise<string | null> {
		try {
			const accessToken = await this.ensureValidToken();
			const escapedName = name.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
			const query = `name='${escapedName}' and '${parentId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`;

			const response = await requestUrl({
				url: `${GoogleDriveProvider.API_URL}/files?q=${encodeURIComponent(query)}&fields=files(id)`,
				method: 'GET',
				headers: { 'Authorization': `Bearer ${accessToken}` }
			});

			if (response.status === 200) {
				const data = response.json;
				if (data.files?.length > 0 && data.files[0].id) {
					return data.files[0].id;
				}
			}
			return null;
		} catch {
			return null;
		}
	}

	private async createFolder(name: string, parentId: string): Promise<string> {
		const accessToken = await this.ensureValidToken();

		const response = await requestUrl({
			url: `${GoogleDriveProvider.API_URL}/files`,
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${accessToken}`,
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({
				name,
				mimeType: 'application/vnd.google-apps.folder',
				parents: [parentId]
			})
		});

		if (response.status !== 200) {
			throw new Error(`Folder creation failed: ${response.status}`);
		}

		return response.json.id;
	}

	private async makeFilePublic(fileId: string, accessToken: string): Promise<void> {
		try {
			await requestUrl({
				url: `${GoogleDriveProvider.API_URL}/files/${fileId}/permissions`,
				method: 'POST',
				headers: {
					'Authorization': `Bearer ${accessToken}`,
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({ role: 'reader', type: 'anyone' })
			});
		} catch (error) {
			console.error('[cmds-eagle] Failed to make file public:', error);
		}
	}

	private async getFileInfo(fileId: string, accessToken: string): Promise<{ webViewLink?: string; webContentLink?: string }> {
		try {
			const response = await requestUrl({
				url: `${GoogleDriveProvider.API_URL}/files/${fileId}?fields=webViewLink,webContentLink`,
				method: 'GET',
				headers: { 'Authorization': `Bearer ${accessToken}` }
			});
			return response.json as { webViewLink?: string; webContentLink?: string };
		} catch {
			return {};
		}
	}

	// ── PKCE helpers ────────────────────────────────────

	private generateCodeVerifier(): string {
		const array = new Uint8Array(32);
		crypto.getRandomValues(array);
		return this.base64UrlEncode(array);
	}

	private async generateCodeChallenge(verifier: string): Promise<string> {
		const data = new TextEncoder().encode(verifier);
		const hash = await crypto.subtle.digest('SHA-256', data);
		return this.base64UrlEncode(new Uint8Array(hash));
	}

	private base64UrlEncode(buffer: Uint8Array): string {
		let binary = '';
		for (let i = 0; i < buffer.length; i++) {
			binary += String.fromCharCode(buffer[i]);
		}
		return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	}

	// ── Utilities ───────────────────────────────────────

	private cleanupServer(): void {
		if (this.timeoutId) {
			clearTimeout(this.timeoutId);
			this.timeoutId = null;
		}
		if (this.server) {
			this.server.close();
			this.server = null;
		}
	}

	private getResultHtml(success: boolean, error?: string): string {
		if (success) {
			return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CMDS Eagle - Google Drive Connected</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:linear-gradient(135deg,#4285f4,#34a853)}.c{background:#fff;padding:40px 60px;border-radius:16px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.2)}</style>
</head><body><div class="c"><div style="font-size:64px">✅</div><h1>Connected!</h1><p>Google Drive is connected. You can close this window.</p></div></body></html>`;
		}
		return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CMDS Eagle - Connection Failed</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:linear-gradient(135deg,#ea4335,#fbbc05)}.c{background:#fff;padding:40px 60px;border-radius:16px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.2)}.e{background:#fff3f3;border:1px solid #fcc;padding:10px 20px;border-radius:8px;color:#c00;font-family:monospace}</style>
</head><body><div class="c"><div style="font-size:64px">❌</div><h1>Failed</h1><div class="e">${error || 'Unknown error'}</div><p>Please try again in Obsidian.</p></div></body></html>`;
	}
}

export function createCloudProvider(config: AnyCloudProviderConfig): CloudProvider | null {
	switch (config.type) {
		case 'r2':
			return new R2Provider(config as R2ProviderConfig);
		case 's3':
			return new S3Provider(config as S3ProviderConfig);
		case 'webdav':
			return new WebDAVProvider(config as WebDAVProviderConfig);
		case 'imghippo':
			return new ImgHippoProvider(config as ImgHippoProviderConfig);
		case 'custom':
			return new CustomProvider(config as CustomProviderConfig);
		case 'googledrive':
			return new GoogleDriveProvider(config as GoogleDriveProviderConfig);
		default:
			return null;
	}
}

export function getExtFromFilename(filename: string): string {
	const parts = filename.split('.');
	return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}

export { getMimeType };
