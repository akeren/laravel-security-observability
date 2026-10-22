<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function getConnection(): ?string
    {
        return config('security-observability.delivery.connection');
    }

    public function up(): void
    {
        $schema = Schema::connection($this->getConnection());
        $schema->create('security_observability_state', function (Blueprint $table): void {
            $table->unsignedInteger('id')->primary();
            $table->unsignedInteger('lock_marker')->default(0);
            $table->unsignedBigInteger('rejected')->default(0);
            $table->unsignedBigInteger('stored_rows')->default(0);
            $table->unsignedBigInteger('stored_bytes')->default(0);
            $table->boolean('capacity_rejected')->default(false);
            $table->bigInteger('last_success')->nullable();
        });
        DB::connection($this->getConnection())->table('security_observability_state')->insert(['id' => 1]);
        $schema->create('security_observability_outbox', function (Blueprint $table): void {
            $table->string('event_id', 64)->primary();
            $table->text('payload');
            $table->unsignedInteger('bytes');
            $table->string('status', 16)->index();
            $table->unsignedInteger('attempts')->default(0);
            $table->bigInteger('created_at');
            $table->bigInteger('next_attempt')->index();
            $table->bigInteger('lease_until')->nullable();
            $table->string('lease_token', 64)->nullable();
            $table->string('failure', 32)->nullable();
            $table->bigInteger('delivered_at')->nullable();
        });
    }

    public function down(): void
    {
        $schema = Schema::connection($this->getConnection());
        $schema->dropIfExists('security_observability_outbox');
        $schema->dropIfExists('security_observability_state');
    }
};
