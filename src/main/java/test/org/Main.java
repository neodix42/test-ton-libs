package test.org;

import com.iwebpp.crypto.TweetNaclFast;
import org.ton.java.address.Address;
import org.ton.java.cell.Cell;
import org.ton.java.cell.CellBuilder;
import org.ton.java.emulator.EmulateTransactionResult;
import org.ton.java.emulator.tvm.*;
import org.ton.java.emulator.tx.TxEmulator;
import org.ton.java.emulator.tx.TxVerbosityLevel;
import org.ton.java.smartcontract.types.WalletV4R2Config;
import org.ton.java.smartcontract.types.WalletV5Config;
import org.ton.java.smartcontract.wallet.v4.WalletV4R2;
import org.ton.java.smartcontract.wallet.v5.WalletV5;
import org.ton.java.tlb.types.*;
import org.ton.java.tonlib.Tonlib;
import org.ton.java.tonlib.types.*;
import org.ton.java.tonlib.types.BlockIdExt;
import org.ton.java.utils.Utils;

import org.ton.java.smartcontract.types.Destination;

import java.io.File;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Collections;

public class Main {

  private static final String CURRENT_DIR = System.getProperty("user.dir");

  public static void main(String[] args) {

    if (args.length != 0) {

      System.out.println("Specified path: " + args[0]);

      String absolutePathTonlib;
      String absolutePathEmulator;

      if (args[0].contains("/") || args[0].contains("\\") || args[0].contains(":")) {
        absolutePathTonlib = args[0];
      } else {
        absolutePathTonlib = CURRENT_DIR + File.separator + args[0];
      }

      System.out.println("Found tonlib: " + absolutePathTonlib);
      System.out.println();

      Tonlib tonlib =
          Tonlib.builder()
              .testnet(false)
              .pathToTonlibSharedLib(absolutePathTonlib)
              .verbosityLevel(VerbosityLevel.FATAL)
              .ignoreCache(false)
              .build();

      if (args.length == 1) { // test tonlib only
        testTonlib(tonlib);

      } else { // test emulator - requires tonlib

        if (args[1].contains("/") || args[1].contains("\\") || args[1].contains(":")) {
          absolutePathEmulator = args[1];
        } else {
          absolutePathEmulator = CURRENT_DIR + File.separator + args[1];
        }

        System.out.println("Found emulator: " + absolutePathEmulator);
        System.out.println();

        testTonlib(tonlib);

        Cell config = tonlib.getConfigAll(128);
        TxEmulator txEmulator =
            TxEmulator.builder()
                .pathToEmulatorSharedLib(absolutePathEmulator)
                .customConfig(config.toBase64())
                .verbosityLevel(TxVerbosityLevel.TRUNCATED)
                .build();

        testTxEmulator(txEmulator);
        testTvmEmulator(tonlib, absolutePathEmulator);
      }
    } else {
      System.out.println(
          "Usage: test-ton4j.jar <name in current dir or absolute path to tonlibjson>");
      System.out.println(
          "Usage: test-ton4j.jar <name in current dir or absolute path to tonlibjson and emulator>");
    }
  }

  private static void testTxEmulator(TxEmulator txEmulator) {
    try {
      testTxEmulatorEmptyAccount(txEmulator);
      testTxEmulatorWithAccount(txEmulator);
      testTxEmulatorEmulateTickTx(txEmulator);
      testTxEmulatorWalletV5ExternalMsgSimplified(txEmulator);
      testTxEmulatorWalletV5InternalMsg(txEmulator);

      System.out.println();
      System.out.println("TxEmulator tests PASSED");
      System.out.println();
    } catch (Throwable e) {
      System.out.println();
      System.out.println("TxEmulator tests FAILED");
      System.out.println();
    }
  }

  private static void testTvmEmulator(Tonlib tonlib, String absolutePathEmulator) {
    try {

      byte[] secretKey =
          Utils.hexToSignedBytes(
              "F182111193F30D79D517F2339A1BA7C25FDF6C52142F0F2C1D960A1F1D65E1E4");
      TweetNaclFast.Signature.KeyPair keyPair = TweetNaclFast.Signature.keyPair_fromSeed(secretKey);

      WalletV4R2 walletV4R2 =
          WalletV4R2.builder().tonlib(tonlib).keyPair(keyPair).walletId(42).build();

      Cell code = walletV4R2.getStateInit().getCode();
      Cell data = walletV4R2.getStateInit().getData();

      TvmEmulator tvmEmulator =
          TvmEmulator.builder()
              .pathToEmulatorSharedLib(absolutePathEmulator)
              .codeBoc(code.toBase64())
              .dataBoc(data.toBase64())
              .verbosityLevel(TvmVerbosityLevel.TRUNCATED)
              .build();

      tvmEmulator.setDebugEnabled(true);
      tvmEmulator.setGasLimit(200000);

      testTvmEmulatorEmulateRunMethod(tvmEmulator);
      testTvmEmulatorSendExternalMessage(tvmEmulator, walletV4R2);
      testTvmEmulatorSendInternalMessage(tvmEmulator);

      System.out.println();
      System.out.println("TvmEmulator tests PASSED");
      System.out.println();
    } catch (Throwable e) {
      System.out.println();
      System.out.println("TvmEmulator tests FAILED");
      System.out.println(e.getMessage());
    }
  }

  private static void testTonlib(Tonlib tonlib) {

    try {
      System.out.println("Testing tonlib.getLast()...");
      MasterChainInfo masterChainInfo = tonlib.getLast();
      System.out.println(masterChainInfo);

      System.out.println("Testing tonlib.getConfigAll(128)...");
      System.out.println(tonlib.getConfigAll(128));

      System.out.println("Testing tonlib.getBlockTransactions(last)...");
      BlockTransactions blockTransactions =
          tonlib.getBlockTransactions(masterChainInfo.getLast(), 10);
      System.out.println(blockTransactions);

      String account =
          "-1:" + Utils.base64ToHexString(blockTransactions.getTransactions().get(0).getAccount());
      System.out.println("Testing tonlib.getAccountState(" + account + ")...");
      System.out.println(tonlib.getAccountState(Address.of(account)).getBalance());

      System.out.println("Testing tonlib.getRawTransactions(" + account + ")...");
      RawTransactions rawTransactions = tonlib.getRawTransactions(account, null, null);
      System.out.println(rawTransactions.getTransactions().size());

      System.out.println("Testing tonlib.lookupBlock()...");
      BlockIdExt lookupBlock =
          tonlib.lookupBlock(
              masterChainInfo.getLast().getSeqno(),
              masterChainInfo.getLast().getWorkchain(),
              masterChainInfo.getLast().getShard(),
              0);
      System.out.println(lookupBlock);

      SmcLibraryResult libraryResult =
          tonlib.getLibraries(
              Collections.singletonList("wkUmK4wrzl6fzSPKM04dVfqW1M5pqigX3tcXzvy6P3M="));
      System.out.println(libraryResult);

      System.out.println();
      System.out.println("Tonlib tests PASSED");
      System.out.println();
    } catch (Throwable e) {
      System.out.println();
      System.out.println("Tonlib tests FAILED");
      System.out.println(e.getMessage());
    }
  }

  private static void testTxEmulatorEmptyAccount(TxEmulator txEmulator) {
    ShardAccount shardAccount =
        ShardAccount.builder()
            .account(Account.builder().isNone(true).build())
            .lastTransHash(BigInteger.ZERO)
            .lastTransLt(BigInteger.ZERO)
            .build();
    String shardAccountBocBase64 = shardAccount.toCell().toBase64();

    Message internalMsg =
        Message.builder()
            .info(
                InternalMessageInfo.builder()
                    .srcAddr(
                        MsgAddressIntStd.builder()
                            .workchainId((byte) 0)
                            .address(BigInteger.ZERO)
                            .build())
                    .dstAddr(
                        MsgAddressIntStd.builder()
                            .workchainId((byte) 0)
                            .address(BigInteger.ZERO)
                            .build())
                    .value(CurrencyCollection.builder().coins(Utils.toNano(1)).build())
                    .bounce(false)
                    .createdAt(0)
                    .build())
            .init(null)
            .body(null)
            .build();
    String internalMsgBocBase64 = internalMsg.toCell().toBase64();
    EmulateTransactionResult result =
        txEmulator.emulateTransaction(shardAccountBocBase64, internalMsgBocBase64);
    System.out.println(result.isSuccess());
  }

  private static void testTxEmulatorWithAccount(TxEmulator txEmulator) {
    ShardAccount shardAccount =
        ShardAccount.builder()
            .account(testAccount)
            .lastTransHash(BigInteger.ZERO)
            .lastTransLt(BigInteger.ZERO)
            .build();
    String shardAccountBocBase64 = shardAccount.toCell().toBase64();

    Message internalMsg =
        Message.builder()
            .info(
                InternalMessageInfo.builder()
                    .srcAddr(
                        MsgAddressIntStd.builder()
                            .workchainId((byte) 0)
                            .address(BigInteger.ZERO)
                            .build())
                    .dstAddr(
                        MsgAddressIntStd.builder()
                            .workchainId((byte) 0)
                            .address(BigInteger.ZERO)
                            .build())
                    .value(CurrencyCollection.builder().coins(Utils.toNano(1)).build())
                    .bounce(false)
                    .createdAt(0)
                    .build())
            .init(null)
            .body(null)
            .build();
    String internalMsgBocBase64 = internalMsg.toCell().toBase64();
    EmulateTransactionResult result =
        txEmulator.emulateTransaction(shardAccountBocBase64, internalMsgBocBase64);
    System.out.println(result.isSuccess());
  }

  private static void testTxEmulatorEmulateTickTx(TxEmulator txEmulator) {
    ShardAccount shardAccount =
        ShardAccount.builder()
            .account(testAccount)
            .lastTransHash(BigInteger.valueOf(2))
            .lastTransLt(BigInteger.ZERO)
            .build();

    String shardAccountBocBase64 = shardAccount.toCell().toBase64();

    EmulateTransactionResult result =
        txEmulator.emulateTickTockTransaction(shardAccountBocBase64, false);
    System.out.println(result.isSuccess());
  }

  private static void testTxEmulatorWalletV5ExternalMsgSimplified(TxEmulator txEmulator) {

    Cell codeCell =
        Cell.fromBoc(
            "b5ee9c7241021401000281000114ff00f4a413f4bcf2c80b01020120020302014804050102f20602dcd020d749c120915b8f6320d70b1f2082106578746ebd21821073696e74bdb0925f03e082106578746eba8eb48020d72101d074d721fa4030fa44f828fa443058bd915be0ed44d0810141d721f4058307f40e6fa1319130e18040d721707fdb3ce03120d749810280b99130e070e210070201200809011e20d70b1f82107369676ebaf2e08a7f0701e68ef0eda2edfb218308d722028308d723208020d721d31fd31fd31fed44d0d200d31f20d31fd3ffd70a000af90140ccf9109a28945f0adb31e1f2c087df02b35007b0f2d0845125baf2e0855036baf2e086f823bbf2d0882292f800de01a47fc8ca00cb1f01cf16c9ed542092f80fde70db3cd8100201200a0b0019be5f0f6a2684080a0eb90fa02c02016e0c0d0201480e0f0019adce76a2684020eb90eb85ffc00019af1df6a2684010eb90eb858fc00017b325fb51341c75c875c2c7e00011b262fb513435c2802003f6eda2edfb02f404216e926c218e4c0221d73930709421c700b38e2d01d72820761e436c20d749c008f2e09320d74ac002f2e09320d71d06c712c2005230b0f2d089d74cd7393001a4e86c128407bbf2e093d74ac000f2e093ed55e2d20001c000915be0ebd72c08142091709601d72c081c12e25210b1e30f20d74a111213009601fa4001fa44f828fa443058baf2e091ed44d0810141d718f405049d7fc8ca0040048307f453f2e08b8e14038307f45bf2e08c22d70a00216e01b3b0f2d090e2c85003cf1612f400c9ed54007230d72c08248e2d21f2e092d200ed44d0d2005113baf2d08f54503091319c01810140d721d70a00f2e08ee2c8ca0058cf16c9ed5493f2c08de20010935bdb31e1d74cd0b574c194");

    byte[] secretKey =
        Utils.hexToSignedBytes("F182111193F30D79D517F2339A1BA7C25FDF6C52142F0F2C1D960A1F1D65E1E4");
    TweetNaclFast.Signature.KeyPair keyPair = TweetNaclFast.Signature.keyPair_fromSeed(secretKey);

    WalletV5 walletV5 =
        WalletV5.builder()
            .keyPair(keyPair)
            .isSigAuthAllowed(false)
            .initialSeqno(0)
            .walletId(42)
            .build();

    Cell dataCell = walletV5.createDataCell();

    String rawDummyDestinationAddress =
        "0:258e549638a6980ae5d3c76382afd3f4f32e34482dafc3751e3358589c8de00d";

    WalletV5Config walletV5Config =
        WalletV5Config.builder()
            .seqno(0)
            .walletId(42)
            .body(
                walletV5
                    .createBulkTransfer(
                        Collections.singletonList(
                            Destination.builder()
                                .bounce(false)
                                .address(rawDummyDestinationAddress)
                                .amount(Utils.toNano(1))
                                .build()))
                    .toCell())
            .build();

    Message extMsg = walletV5.prepareExternalMsg(walletV5Config);

    EmulateTransactionResult result =
        txEmulator.emulateTransaction(
            codeCell, dataCell, Utils.toNano(2), extMsg.toCell().toBase64());
    System.out.println(result.isSuccess());
  }

  private static void testTxEmulatorWalletV5InternalMsg(TxEmulator txEmulator) {

    Cell codeCell =
        Cell.fromBoc(
            "b5ee9c7241021401000281000114ff00f4a413f4bcf2c80b01020120020302014804050102f20602dcd020d749c120915b8f6320d70b1f2082106578746ebd21821073696e74bdb0925f03e082106578746eba8eb48020d72101d074d721fa4030fa44f828fa443058bd915be0ed44d0810141d721f4058307f40e6fa1319130e18040d721707fdb3ce03120d749810280b99130e070e210070201200809011e20d70b1f82107369676ebaf2e08a7f0701e68ef0eda2edfb218308d722028308d723208020d721d31fd31fd31fed44d0d200d31f20d31fd3ffd70a000af90140ccf9109a28945f0adb31e1f2c087df02b35007b0f2d0845125baf2e0855036baf2e086f823bbf2d0882292f800de01a47fc8ca00cb1f01cf16c9ed542092f80fde70db3cd8100201200a0b0019be5f0f6a2684080a0eb90fa02c02016e0c0d0201480e0f0019adce76a2684020eb90eb85ffc00019af1df6a2684010eb90eb858fc00017b325fb51341c75c875c2c7e00011b262fb513435c2802003f6eda2edfb02f404216e926c218e4c0221d73930709421c700b38e2d01d72820761e436c20d749c008f2e09320d74ac002f2e09320d71d06c712c2005230b0f2d089d74cd7393001a4e86c128407bbf2e093d74ac000f2e093ed55e2d20001c000915be0ebd72c08142091709601d72c081c12e25210b1e30f20d74a111213009601fa4001fa44f828fa443058baf2e091ed44d0810141d718f405049d7fc8ca0040048307f453f2e08b8e14038307f45bf2e08c22d70a00216e01b3b0f2d090e2c85003cf1612f400c9ed54007230d72c08248e2d21f2e092d200ed44d0d2005113baf2d08f54503091319c01810140d721d70a00f2e08ee2c8ca0058cf16c9ed5493f2c08de20010935bdb31e1d74cd0b574c194");

    byte[] secretKey =
        Utils.hexToSignedBytes("F182111193F30D79D517F2339A1BA7C25FDF6C52142F0F2C1D960A1F1D65E1E4");
    TweetNaclFast.Signature.KeyPair keyPair = TweetNaclFast.Signature.keyPair_fromSeed(secretKey);

    WalletV5 walletV5 =
        WalletV5.builder()
            .keyPair(keyPair)
            .isSigAuthAllowed(false)
            .initialSeqno(0)
            .walletId(42)
            .build();

    Cell dataCell = walletV5.createDataCell();

    Address address = StateInit.builder().code(codeCell).data(dataCell).build().getAddress();

    Account walletV5Account =
        Account.builder()
            .isNone(false)
            .address(MsgAddressIntStd.of(address))
            .storageInfo(
                StorageInfo.builder()
                    .storageUsed(
                        StorageUsed.builder()
                            .cellsUsed(BigInteger.ZERO)
                            .bitsUsed(BigInteger.ZERO)
                            .publicCellsUsed(BigInteger.ZERO)
                            .build())
                    .lastPaid(System.currentTimeMillis() / 1000)
                    .duePayment(BigInteger.ZERO)
                    .build())
            .accountStorage(
                AccountStorage.builder()
                    .lastTransactionLt(BigInteger.ZERO)
                    .balance(
                        CurrencyCollection.builder()
                            .coins(Utils.toNano(5)) // initial balance
                            .build())
                    .accountState(
                        AccountStateActive.builder()
                            .stateInit(StateInit.builder().code(codeCell).data(dataCell).build())
                            .build())
                    .build())
            .build();

    ShardAccount shardAccount =
        ShardAccount.builder()
            .account(walletV5Account)
            .lastTransHash(BigInteger.ZERO)
            .lastTransLt(BigInteger.ZERO)
            .build();
    String shardAccountBocBase64 = shardAccount.toCell().toBase64();

    txEmulator.setDebugEnabled(true);

    String rawDummyDestinationAddress =
        "0:258e549638a6980ae5d3c76382afd3f4f32e34482dafc3751e3358589c8de00d";

    WalletV5Config walletV5Config =
        WalletV5Config.builder()
            .seqno(0)
            .walletId(42)
            .amount(Utils.toNano(0.1))
            .body(
                walletV5
                    .createBulkTransfer(
                        Collections.singletonList(
                            Destination.builder()
                                .bounce(false)
                                .address(rawDummyDestinationAddress)
                                .amount(Utils.toNano(1))
                                .build()))
                    .toCell())
            .build();

    Message intMsg = walletV5.prepareInternalMsg(walletV5Config);

    EmulateTransactionResult result =
        txEmulator.emulateTransaction(shardAccountBocBase64, intMsg.toCell().toBase64());

    System.out.println(result.isSuccess());

    ShardAccount newShardAccount = result.getNewShardAccount();

    TransactionDescription txDesc = result.getTransaction().getDescription();

    TransactionDescriptionOrdinary txDescOrd = (TransactionDescriptionOrdinary) txDesc;

    ComputePhaseVM computePhase = (ComputePhaseVM) txDescOrd.getComputePhase();
    System.out.println(computePhase.isSuccess());

    ActionPhase actionPhase = txDescOrd.getActionPhase();
    System.out.println(actionPhase.isSuccess());

    // second transfer using new shard account

    walletV5Config =
        WalletV5Config.builder()
            .seqno(1)
            .walletId(42)
            .amount(Utils.toNano(0.1))
            .body(
                walletV5
                    .createBulkTransfer(
                        Collections.singletonList(
                            Destination.builder()
                                .bounce(false)
                                .address(rawDummyDestinationAddress)
                                .amount(Utils.toNano(1))
                                .build()))
                    .toCell())
            .build();

    intMsg = walletV5.prepareInternalMsg(walletV5Config);

    result =
        txEmulator.emulateTransaction(
            newShardAccount.toCell().toBase64(), intMsg.toCell().toBase64());

    result.getNewShardAccount();

    txDesc = result.getTransaction().getDescription();

    txDescOrd = (TransactionDescriptionOrdinary) txDesc;

    computePhase = (ComputePhaseVM) txDescOrd.getComputePhase();
    System.out.println(computePhase.isSuccess());

    actionPhase = txDescOrd.getActionPhase();
    System.out.println(actionPhase.isSuccess());
  }

  private static void testTvmEmulatorEmulateRunMethod(TvmEmulator tvmEmulator) {
    GetMethodResult methodResult = tvmEmulator.runGetMethod(Utils.calculateMethodId("seqno"));
    System.out.println("result runGetMethod: " + methodResult.isSuccess());
  }

  private static void testTvmEmulatorSendExternalMessage(
      TvmEmulator tvmEmulator, WalletV4R2 walletV4R2) {
    String address = walletV4R2.getAddress().toBounceable();
    String randSeedHex = Utils.sha256("ABC");
    //        Cell configAll = tonlib.getConfigAll(128);

    tvmEmulator.setC7(
        address, Instant.now().getEpochSecond(), Utils.toNano(1).longValue(), randSeedHex, null);

    WalletV4R2Config config =
        WalletV4R2Config.builder()
            .operation(0)
            .walletId(42)
            .seqno(0)
            .destination(
                Address.of("0:258e549638a6980ae5d3c76382afd3f4f32e34482dafc3751e3358589c8de00d"))
            .amount(Utils.toNano(0.124))
            .build();

    //        assertTrue(tvmEmulator.setLibs(getLibs().toBase64()));

    Message msg = walletV4R2.prepareExternalMsg(config);
    SendExternalMessageResult result = tvmEmulator.sendExternalMessage(msg.getBody().toBase64());

    OutList actions = result.getActions();
    System.out.println("actions "+actions.getActions().size());

    tvmEmulator.runGetSeqNo();

    // send one more time
    config =
        WalletV4R2Config.builder()
            .operation(0)
            .walletId(42)
            .seqno(1)
            .destination(
                Address.of("0:258e549638a6980ae5d3c76382afd3f4f32e34482dafc3751e3358589c8de00d"))
            .amount(Utils.toNano(0.123))
            .build();

    msg = walletV4R2.prepareExternalMsg(config);
    tvmEmulator.sendExternalMessage(msg.getBody().toBase64());

    if (tvmEmulator.runGetSeqNo().longValue() != 2) {
      throw new Error("failed");
    }
  }

  private static void testTvmEmulatorSendInternalMessage(TvmEmulator tvmEmulator) {
    Cell body =
        CellBuilder.beginCell()
            .storeUint(0x706c7567, 32) // op request funds
            .endCell();

    tvmEmulator.setDebugEnabled(false);

    SendInternalMessageResult result =
        tvmEmulator.sendInternalMessage(body.toBase64(), Utils.toNano(0.11).longValue());

    System.out.println("result sendInternalMessage, " + result.isSuccess());

    OutList actions = result.getActions();
    System.out.println("compute phase actions " + actions.getActions().size());
  }

  static Account testAccount =
      Account.builder()
          .isNone(false)
          .address(
              MsgAddressIntStd.of(
                  "-1:0000000000000000000000000000000000000000000000000000000000000000"))
          .storageInfo(
              StorageInfo.builder()
                  .storageUsed(
                      StorageUsed.builder()
                          .cellsUsed(BigInteger.ZERO)
                          .bitsUsed(BigInteger.ZERO)
                          .publicCellsUsed(BigInteger.ZERO)
                          .build())
                  .lastPaid(System.currentTimeMillis() / 1000)
                  .duePayment(Utils.toNano(2))
                  .build())
          .accountStorage(
              AccountStorage.builder()
                  .balance(
                      CurrencyCollection.builder()
                          .coins(Utils.toNano(2)) // initial balance
                          .build())
                  .accountState(
                      AccountStateActive.builder()
                          .stateInit(
                              StateInit.builder()
                                  .code(
                                      CellBuilder.beginCell()
                                          .fromBoc(
                                              "b5ee9c7241010101004e000098ff0020dd2082014c97ba9730ed44d0d70b1fe0a4f260810200d71820d70b1fed44d0d31fd3ffd15112baf2a122f901541044f910f2a2f80001d31f31d307d4d101fb00a4c8cb1fcbffc9ed5470102286")
                                          .endCell())
                                  .build())
                          .build())
                  .accountStatus("ACTIVE")
                  .build())
          .build();
}
