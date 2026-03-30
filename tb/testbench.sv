
// =============================================================================
// Self-checking testbench
// =============================================================================
module tb_aes128;
    logic        clk, rst_n, start, done;
    logic [127:0] plaintext, key, ciphertext;

    aes128 dut (.*);

    initial clk = 0;
    always #5 clk = ~clk;

    initial begin
        rst_n     = 0;
        start     = 0;
        plaintext = 128'h00112233445566778899aabbccddeeff;
        key       = 128'h000102030405060708090a0b0c0d0e0f;

        repeat(2) @(posedge clk); #1;
        rst_n = 1;
        @(posedge clk); #1;
        start = 1;
        @(posedge clk); #1;
        start = 0;

        wait (done);
        @(posedge clk);

        $display("Ciphertext : %h", ciphertext);
        $display("Expected   : 69c4e0d86a7b0430d8cdb78070b4c55a");
        if (ciphertext === 128'h69c4e0d86a7b0430d8cdb78070b4c55a)
            $display("PASS");
        else
            $display("FAIL");
        $finish;
    end
  initial begin
    $dumpfile("simulation_output.vcd");
    $dumpvars(0, tb_aes128); // Dumps all variables in top_module
    #1000 $finish;
end

  
endmodule
