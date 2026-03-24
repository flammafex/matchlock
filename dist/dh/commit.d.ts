import type { MatchToken, CommitHash } from '../types.js';
export declare function commitToken(matchToken: MatchToken): CommitHash;
export declare function commitTokens(matchTokens: MatchToken[]): CommitHash[];
export declare function verifyCommitment(matchToken: MatchToken, commitHash: CommitHash): boolean;
//# sourceMappingURL=commit.d.ts.map