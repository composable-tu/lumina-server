package org.lumina.utils

import org.apache.commons.io.output.ByteArrayOutputStream
import org.apache.poi.xssf.usermodel.XSSFWorkbook

object POIUtil {
    /**
     * 创建 Excel 文件
     * @param sheets 包含工作表名称和数据的映射
     * @return Excel 文件的字节数组
     */
    fun createExcel(sheets: Map<String, List<List<Any?>>>): ByteArray {
        val workbook = XSSFWorkbook()
        try {
            sheets.forEach { (sheetName, sheetData) ->
                val sheet = workbook.createSheet(sheetName)

                sheetData.forEachIndexed { rowIndex, rowData ->
                    val row = sheet.createRow(rowIndex)
                    rowData.forEachIndexed { cellIndex, cellData ->
                        val cell = row.createCell(cellIndex)
                        when (cellData) {
                            is String -> cell.setCellValue(cellData)
                            is Number -> cell.setCellValue(cellData.toDouble())
                            is Boolean -> cell.setCellValue(cellData)
                            null -> cell.setCellValue("")
                            else -> cell.setCellValue(cellData.toString())
                        }
                    }
                }

                // 自动调整列宽
                if (sheetData.isNotEmpty()) {
                    val columnCount = sheetData.maxOfOrNull { it.size } ?: 0
                    for (i in 0 until columnCount) sheet.autoSizeColumn(i)
                }
            }

            val outputStream = ByteArrayOutputStream()
            workbook.use { wb -> wb.write(outputStream) }

            return outputStream.toByteArray()
        } finally {
            workbook.close()
        }
    }

    /**
     * 创建带表头的 Excel 工作表数据
     * @param headers 表头列表
     * @param dataRows 数据行列表
     * @return 包含表头和数据的完整列表
     */
    fun createSheetDataWithHeaders(headers: List<String>, dataRows: List<List<Any?>>): List<List<Any?>> {
        val result = mutableListOf<List<Any?>>()
        result.add(headers)
        result.addAll(dataRows)
        return result
    }
}