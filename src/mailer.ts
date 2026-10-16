export interface WhitelistConfirmation {
  to: string;
  token: string;
  network: string;
  address: string;
}

/** Placeholder for a real email provider. */
export interface Mailer {
  sendWhitelistConfirmation(message: WhitelistConfirmation): Promise<void>;
}

/** Development mailer: prints the message. Never use in production, it logs the confirmation token. */
export class ConsoleMailer implements Mailer {
  async sendWhitelistConfirmation(m: WhitelistConfirmation): Promise<void> {
    console.log(`[mail] to=${m.to} confirm withdrawal address ${m.address} (${m.network}) with token ${m.token}`);
  }
}

/** Test mailer: keeps messages in memory. */
export class MemoryMailer implements Mailer {
  sent: WhitelistConfirmation[] = [];
  async sendWhitelistConfirmation(m: WhitelistConfirmation): Promise<void> {
    this.sent.push(m);
  }
}
