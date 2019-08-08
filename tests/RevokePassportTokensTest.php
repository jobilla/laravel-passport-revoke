<?php

namespace Jobilla\PassportRevoke\Tests;

use Carbon\Carbon;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Jobilla\PassportRevoke\PassportRevokeServiceProvider;
use Jobilla\PassportRevoke\RevokePassportTokens;
use Laravel\Passport\PassportServiceProvider;
use Laravel\Passport\Token;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use Ramsey\Uuid\Uuid;

class RevokePassportTokensTest extends TestCase
{
    use MockeryPHPUnitIntegration, RefreshDatabase;

    public function test_it_can_revoke_a_specific_token()
    {
        $this->createTokens([
            [
                'id' => 'f8097432-b83e-4503-9c83-e3906655a58b',
                'client_id' => 1,
                'revoked' => false,
            ],
            [
                'client_id' => 1,
                'revoked' => false,
            ]
        ]);

        $this->artisan(RevokePassportTokens::class, ['token' => 'f8097432-b83e-4503-9c83-e3906655a58b'])
            ->assertExitCode(0)
            ->run();
        $this->assertEquals(1, Token::query()->where('revoked', false)->count());
        $this->assertEquals(1, Token::query()->where('revoked', true)->count());
    }

    public function test_it_allows_revoking_all_tokens_if_no_conditions_are_passed()
    {
        $this->createTokens([
            [
                'client_id' => 1,
                'revoked' => 0,
            ],
            [
                'client_id' => 1,
                'revoked' => 0,
            ],
            [
                'client_id' => 2,
                'revoked' => 0,
            ],
        ]);

        $this->assertEquals(3, Token::query()->where('revoked', false)->count());

        $this->artisan(RevokePassportTokens::class)
            ->expectsQuestion(
                'You did not provide any user, client or token. All Passport tokens will be revoked. Continue?',
                true
            )
            ->assertExitCode(0)
            ->run();

        $this->assertEquals(3, Token::query()->where('revoked', true)->count());
    }

    public function test_it_does_not_revoke_all_tokens_if_the_user_does_not_confirm()
    {
        $this->createTokens([
            [
                'client_id' => 1,
                'revoked' => 0,
            ],
            [
                'client_id' => 1,
                'revoked' => 0,
            ],
            [
                'client_id' => 2,
                'revoked' => 0,
            ],
        ]);

        $this->assertEquals(3, Token::query()->where('revoked', false)->count());

        $this->artisan(RevokePassportTokens::class)
            ->expectsQuestion(
                'You did not provide any user, client or token. All Passport tokens will be revoked. Continue?',
                false
            )
            ->assertExitCode(0)
            ->run();

        $this->assertEquals(3, Token::query()->where('revoked', false)->count());
    }

    public function test_it_can_revoke_tokens_for_a_given_user()
    {
        $this->createTokens([
            [
                'client_id' => 1,
                'revoked' => 0,
                'user_id' => 1,
            ],
            [
                'client_id' => 1,
                'revoked' => 0,
                'user_id' => 1
            ],
            [
                'client_id' => 2,
                'revoked' => 0,
                'user_id' => 2
            ],
        ]);

        $this->assertEquals(
            2,
            Token::query()->where('revoked', false)->where('user_id', 1)->count()
        );
        $this->assertEquals(
            1,
            Token::query()->where('revoked', false)->where('user_id', 2)->count()
        );

        $this->artisan(RevokePassportTokens::class, ['--user' => '1'])
            ->assertExitCode(0)
            ->run();

        $this->assertEquals(
            2,
            Token::query()->where('revoked', true)->where('user_id', 1)->count()
        );
        $this->assertEquals(
            0,
            Token::query()->where('revoked', true)->where('user_id', 2)->count()
        );
    }

    public function test_it_can_revoke_tokens_for_a_given_client()
    {
        $this->createTokens([
            [
                'client_id' => 1,
                'revoked' => 0,
                'user_id' => 1,
            ],
            [
                'client_id' => 1,
                'revoked' => 0,
                'user_id' => 1
            ],
            [
                'client_id' => 2,
                'revoked' => 0,
                'user_id' => 2
            ],
        ]);

        $this->assertEquals(
            2,
            Token::query()->where('revoked', false)->where('client_id', 1)->count()
        );
        $this->assertEquals(
            1,
            Token::query()->where('revoked', false)->where('client_id', 2)->count()
        );

        $this->artisan(RevokePassportTokens::class, ['--client' => '1'])
            ->assertExitCode(0)
            ->run();

        $this->assertEquals(
            2,
            Token::query()->where('revoked', true)->where('client_id', 1)->count()
        );
        $this->assertEquals(
            0,
            Token::query()->where('revoked', true)->where('client_id', 2)->count()
        );
    }

    public function test_it_can_revoke_tokens_for_a_given_client_and_user()
    {
        $this->createTokens([
            [
                'client_id' => 1,
                'revoked' => 0,
                'user_id' => 1,
            ],
            [
                'client_id' => 1,
                'revoked' => 0,
                'user_id' => 1
            ],
            [
                'client_id' => 2,
                'revoked' => 0,
                'user_id' => 1
            ],
            [
                'client_id' => 2,
                'revoked' => 0,
                'user_id' => 2
            ],
        ]);

        $this->assertEquals(4, Token::query()->where('revoked', false)->count());

        $this->artisan(RevokePassportTokens::class, ['--client' => '2', '--user' => '1'])
            ->assertExitCode(0)
            ->run();

        $this->assertEquals(1, Token::query()->where('revoked', true)->count());
        $this->assertEquals(
            0,
            Token::query()->where('revoked', true)->where('client_id', 1)->count()
        );
        $this->assertEquals(
            0,
            Token::query()->where('revoked', true)->where('user_id', 2)->count()
        );
    }

    protected function getPackageProviders($app)
    {
        return [PassportRevokeServiceProvider::class, PassportServiceProvider::class];
    }

    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function getEnvironmentSetUp($app)
    {
        Carbon::setTestNow('2019-08-05 12:00:00');

        // Setup default database to use sqlite :memory:
        $app['config']->set('database.default', 'testbench');
        $app['config']->set('database.connections.testbench', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }

    private function createTokens(array $tokens)
    {
        Token::query()->insert(array_map(function ($token) {
            return array_merge([
                'id' => Uuid::uuid4()->toString(),
                'expires_at' => Carbon::now()->addMonth(),
                'user_id' => 1,
            ], $token);
        }, $tokens));
    }
}
