/// <reference types="node" />
import type { OutgoingHttpHeaders, Agent } from 'http';
export declare class Request {
    hostname: string;
    headers: OutgoingHttpHeaders;
    failOnLimitReached: boolean;
    agent: Agent | boolean | undefined;
    constructor(hostname: string, { headers, failOnLimitReached, agent }?: {
        headers?: OutgoingHttpHeaders;
        failOnLimitReached?: boolean;
        agent?: Agent | boolean;
    });
    run(method: string, path: string, data?: any): Promise<any>;
}
export default Request;
