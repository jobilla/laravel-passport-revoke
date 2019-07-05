<?php

namespace Jobilla\PassportRevoke;

use Carbon\Carbon;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use Illuminate\Console\Command;
use Laravel\Passport\TokenRepository;
use Symfony\Component\Console\Helper\ProgressBar;

class RevokePassportTokens extends Command
{
    protected $signature = 'passport:revoke {token?} {--user=} {--client=}';
    protected $description = 'Revoke passport tokens';

    public function handle(TokenRepository $tokenRepository)
    {
        if (! ($this->option('user') || $this->argument('token') || $this->option('client'))) {
            $this->confirm(
                'You did not provide any user, client or token. All Passport tokens will be revoked. Continue?'
            );
        }

        if ($token = $this->argument('token')) {
            $this->info("Revoking token $token...");
            $tokenRepository->find($token)->revoke();
            $this->info('✓ Token successfully revoked');

            return;
        }

        $query = Passport::token()->newQuery()
            ->where('revoked', false)
            ->where('expires_at', '>=', Carbon::now());

        if ($user = $this->option('user')) {
            $query->where('user_id', $user);
            $this->info("Revoking all tokens for user $user...");
        } elseif ($client = $this->option('client')) {
            $query->where('client_id', $client);
            $this->info("Revoking all tokens for client $client...");
        } else {
            $this->info('Revoking all active tokens...');
        }

        $progressBar = new ProgressBar($this->getOutput(), $total = $query->count());
        $progressBar->start();

        $query
            ->each(function (Token $token) use ($progressBar) {
                $token->revoke();
                $progressBar->advance();
            });

        $progressBar->finish();
        $this->info("✓ $total tokens revoked");
    }
}
